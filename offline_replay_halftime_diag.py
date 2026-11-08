"""Local capture replay only; never connects to an upstream server.

Run --self-test first, then --seconds 120 to serve. This does not launch or
redirect the game and does not establish game-wide network isolation.
"""
import argparse
from pathlib import Path
import re
import socket
import struct
import threading
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HERE = Path(__file__).resolve().parent


def manual_room_target(step, end_pressed, page_up_pressed):
    """Explicit offline experimental advancement, never driven by other UI clicks."""
    if end_pressed and step == 2:
        return 5
    if page_up_pressed and step == 5:
        return 6
    return step


def room_hotkeys():
    from offline_replay import room_hotkeys as read_keys
    return read_keys()


def records(path):
    result = []
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.fullmatch(r"(OUT|IN) (\S+) sock=(\d+) ([0-9a-f]+)", line)
        if m:
            result.append((m[1], int(m[3]), bytes.fromhex(m[4])))
    return result


def pop_frames(buffer):
    frames = []
    while len(buffer) >= 4:
        if buffer[0] != 0x32:
            raise ValueError("Not a captured 0x32 protocol stream")
        size = 4 + int.from_bytes(buffer[1:3], "little")
        if len(buffer) < size:
            break
        frames.append(bytes(buffer[:size]))
        del buffer[:size]
    return frames


def pop_channel_frames(buffer):
    frames = []
    while len(buffer) >= 3:
        if buffer[:2] != b"\x13\x57" or buffer[2] not in (1, 2):
            raise ValueError("Invalid channel frame")
        head = 3 + buffer[2]
        if len(buffer) < head:
            break
        size = head + int.from_bytes(buffer[3:head], "little")
        if len(buffer) < size:
            break
        frames.append(bytes(buffer[:size]))
        del buffer[:size]
    return frames


def channel_bootstrap(path):
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"\[18030 (C>S|S>C)\] (\d+)B ([0-9a-f]+)", line)
        if match:
            direction, size, text = match.groups()
            data = bytes.fromhex(text)
            if len(data) != int(size):
                raise ValueError("Channel capture byte count mismatch")
            rows.append(("OUT" if direction == "C>S" else "IN", 18030, data))
    groups = exchanges(rows, 18030)[:2]
    if len(groups) != 2:
        raise ValueError("Missing channel bootstrap")
    for request, response in groups:
        for data in (request, response):
            buffer = bytearray(data)
            if len(pop_channel_frames(buffer)) != 1 or buffer:
                raise ValueError("Expected one complete bootstrap frame")
    return groups


def channel_initial_sync(path):
    """Retain only the first captured post-auth sync response, not later chat."""
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"\[18030 (C>S|S>C)\] (\d+)B ([0-9a-f]+)", line)
        if match:
            direction, size, text = match.groups()
            data = bytes.fromhex(text)
            if len(data) != int(size):
                raise ValueError("Channel capture byte count mismatch")
            rows.append((direction, data))
    for index, (direction, data) in enumerate(rows):
        if direction == "C>S" and len(data) == 120 and data[:8] == bytes.fromhex("1357017425010170"):
            replies = bytearray()
            for next_direction, chunk in rows[index + 1:]:
                if next_direction == "C>S":
                    break
                replies.extend(chunk)
            buffer = bytearray(replies)
            if not pop_channel_frames(buffer) or buffer:
                raise ValueError("Incomplete channel sync capture")
            return data, bytes(replies)
    raise ValueError("No initial sync capture")


def is_heartbeat(frame):
    return len(frame) == 5 and frame[:2] == b"\x13\x57" and frame[2] == 1 and frame[4] == 0x1c


def channel_frame_matches(expected, actual, experimental):
    if expected == actual:
        return True
    if not experimental or len(expected) != len(actual):
        return False
    # Session/time fields legitimately differ offline; the frame type must not.
    prefix = 9 if len(expected) == 219 else 5
    return expected[:prefix] == actual[:prefix]


def channel_group_matches(expected, actual, experimental):
    return (len(expected) == len(actual)
            and all(channel_frame_matches(a, b, experimental)
                    for a, b in zip(expected, actual)))


def channel_plan(path):
    """Return (setup, trigger, tail, control) for the full 18030 replay.

    setup: bootstrap, auth and initial-sync request/reply groups.
    trigger: the fourth request group; its reply starts the world stream.
    tail: every server frame from that reply onward, except 15-byte ping
    replies, which are served only when the client sends the matching request.
    """
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.fullmatch(r"\[18030 (C>S|S>C)\] (\d+)B ([0-9a-f]+)", line)
        if match:
            direction, size, text = match.groups()
            data = bytes.fromhex(text)
            if len(data) != int(size):
                raise ValueError("Channel capture byte count mismatch")
            rows.append(("OUT" if direction == "C>S" else "IN", 18030, data))
    groups = exchanges(rows, 18030)
    if len(groups) < 4:
        raise ValueError("Channel capture is missing the setup groups")

    setup = []
    for request, reply in groups[:3]:
        buffer = bytearray(request)
        frames = tuple(pop_channel_frames(buffer))
        if buffer:
            raise ValueError("Incomplete channel setup request")
        setup.append((frames, reply))
    request, _ = groups[3]
    buffer = bytearray(request)
    trigger = tuple(pop_channel_frames(buffer))
    if buffer:
        raise ValueError("Incomplete channel trigger request")

    if tuple(len(frame) for frame in setup[0][0]) != (9,):
        raise ValueError("Channel bootstrap request changed")
    if tuple(len(frame) for frame in setup[1][0]) != (219,):
        raise ValueError("Channel auth request changed")
    if 120 not in [len(frame) for frame in setup[2][0]]:
        raise ValueError("Channel initial sync request changed")
    if 88 not in [len(frame) for frame in trigger]:
        raise ValueError("Channel world trigger request changed")

    # Group boundaries are only recv boundaries: one big server frame can span
    # several groups, so parse the whole tail as one stream.
    buffer = bytearray(b"".join(reply for _, reply in groups[3:]))
    tail = pop_channel_frames(buffer)
    if buffer:
        raise ValueError("Channel capture ends with a partial server frame")
    control = next((frame for frame in tail
                    if len(frame) == 15 and frame[:5] == bytes.fromhex("1357010b01")), None)
    tail = [frame for frame in tail
            if not (len(frame) == 15 and frame[:5] == bytes.fromhex("1357010b01"))]
    return setup, trigger, tail, control


def latest_capture():
    pointer = HERE / "latest_capture.txt"
    if pointer.exists():
        path = Path(pointer.read_text(encoding="utf-8").strip())
        if path.exists():
            return path
    return None


def forced_session_key(path):
    from offline_replay import forced_session_key as read_key
    return read_key(path)


def exchanges(rows, sock):
    groups = []
    requests = bytearray()
    replies = bytearray()
    for direction, handle, data in rows:
        if handle != sock:
            continue
        if direction == "OUT":
            if replies:
                groups.append((bytes(requests), bytes(replies)))
                requests.clear()
                replies.clear()
            requests.extend(data)
        else:
            if not requests:
                raise ValueError("Capture starts with an unsolicited response")
            replies.extend(data)
    if replies:
        groups.append((bytes(requests), bytes(replies)))
    return groups


def signatures(data):
    buffer = bytearray(data)
    result = [frame[:4] for frame in pop_frames(buffer)]
    if buffer:
        raise ValueError("Incomplete request in capture")
    return result


def channel_matches(expected, actual, experimental=False):
    if expected == actual:
        return True
    # shortcut: experimental replay accepts only the captured auth envelope;
    # opaque session bytes are NOT decoded or validated. Local fixture use only.
    return (experimental and len(expected) == len(actual) == 219
            and expected[:9] == actual[:9] == bytes.fromhex("135702d60005028000"))


def captured_control_reply(frame):
    # Exact adjacent request/reply in proxy.log; do not generalize unknown fields.
    if frame == bytes.fromhex("1357010b0101fa0000000000000000"):
        return bytes.fromhex("1357010b0120f60000000000000000")
    return None


# One live training session, 2026-11-02. Groups are the capture's own
# request/response boundaries, so a partial replay cannot desync the client.
ROOM_CAPTURE = HERE / "capture-20261102-214344.log"
ROOM_SHAPE = (
    ((285,),
     (28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 55,
      28, 28, 28, 28, 12, 12, 28, 28, 28, 28, 28, 28, 28, 28, 28),
     (28, 28, 28, 285),
     (28, 28),
     (285,),
     (28,)),
    (1409, 157672, 4195, 88, 249, 43),
)
MATCH_CAPTURE = ROOM_CAPTURE
MATCH_HANDSHAKE_SHAPE = (((9,), (210,)), ((219,), (44, 24)),
                         ((21, 5, 8), (21, 21)), ((5, 56, 5), (308, 20, 45, 13)))
OLD_MATCH_HANDSHAKE_SHAPE = (((9,), (210,)), ((219,), (45, 24)),
                             ((21, 5, 8), (21, 21)), ((5, 56), (308, 20, 45, 13)))


def room_phases(path):
    """Return ((request_frame_lengths, exact reply bytes), ...) for one live session.

    The whole 8001 session comes from the same capture so the server sequence
    numbers stay continuous. Requests are matched by frame size only: the local
    client sends the same sizes with different identities inside the payloads.
    """
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.fullmatch(r"\[8001 (C>S|S>C)\] (\d+)B ([0-9a-f]+)", line)
        if match:
            rows.append(("OUT" if match.group(1) == "C>S" else "IN", 8001,
                         bytes.fromhex(match.group(3))))
    groups = exchanges(rows, 8001)
    shaped = []
    for request, reply in groups:
        request_buffer = bytearray(request)
        frames = pop_frames(request_buffer)
        reply_buffer = bytearray(reply)
        pop_frames(reply_buffer)
        if request_buffer or reply_buffer:
            raise ValueError("Incomplete room capture frame")
        shaped.append((tuple(len(frame) for frame in frames), reply))
    # Extra lobby/heartbeat groups may surround the six room groups; find them.
    for offset in range(len(shaped) - len(ROOM_SHAPE[0]) + 1):
        window = shaped[offset:offset + len(ROOM_SHAPE[0])]
        if (tuple(sizes for sizes, _ in window) == ROOM_SHAPE[0]
                and all(len(reply) == expected for index, ((_, reply), expected)
                        in enumerate(zip(window, ROOM_SHAPE[1])) if index != 1)
                and window[1][1]):
            return window
    sizes = tuple(len(request) for request, _ in groups)
    replies = tuple(len(reply) for _, reply in groups)
    raise ValueError(f"Room capture shape changed: {sizes} / {replies}")


def lobby_stream(path):
    """Return the whole captured 8001 server stream, frame-aligned."""
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.fullmatch(r"\[8001 (C>S|S>C)\] (\d+)B ([0-9a-f]+)", line)
        if match:
            rows.append(("OUT" if match.group(1) == "C>S" else "IN", 8001,
                         bytes.fromhex(match.group(3))))
    stream = b"".join(reply for _, reply in exchanges(rows, 8001))
    buffer = bytearray(stream)
    frames = pop_frames(buffer)
    if buffer or not frames:
        raise ValueError("Lobby capture is not frame-aligned")
    sequences = [frame[3] for frame in frames]
    if any((b - a) % 256 != 1 for a, b in zip(sequences, sequences[1:])):
        raise ValueError("Lobby capture sequence numbers are not continuous")
    return stream


def match_port(path):
    """Find the live match TCP port from the capture; earlier runs used 18020."""
    ports = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.match(r"\[(18\d{3}) (C>S|S>C)\]", line)
        if match:
            port = int(match.group(1))
            if 18020 <= port <= 18029:
                ports.add(port)
    for port in sorted(ports):
        rows = match_rows(path, port)
        groups = exchanges(rows, port)
        shapes = []
        for request, reply in groups[:4]:
            buffer = bytearray(reply)
            shapes.append(tuple(len(frame) for frame in pop_channel_frames(buffer)))
        if shapes in ([a[1] for a in MATCH_HANDSHAKE_SHAPE],
                      [a[1] for a in OLD_MATCH_HANDSHAKE_SHAPE]):
            return port
    raise ValueError("No 18020-18029 match handshake found in capture")


def match_rows(path, port):
    rows = []
    pattern = re.compile(r"\[" + str(port) + r" (C>S|S>C)\] (\d+)B ([0-9a-f]+)")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = pattern.fullmatch(line)
        if match:
            rows.append(("OUT" if match.group(1) == "C>S" else "IN", port,
                         bytes.fromhex(match.group(3))))
    return rows


def halftime_responses(path):
    """Extract the four server frames sent after the captured second-half report."""
    ports = {int(m.group(1)) for line in path.read_text(
        encoding="utf-8", errors="replace").splitlines()
             if (m := re.match(r"\[(18\d{3}) (?:C>S|S>C)\]", line))}
    for port in sorted(ports):
        buffers = {"OUT": bytearray(), "IN": bytearray()}
        events = []
        for direction, _, data in match_rows(path, port):
            buffers[direction].extend(data)
            events.extend((direction, frame)
                          for frame in pop_channel_frames(buffers[direction]))
        trigger = next((i for i, (direction, frame) in enumerate(events)
                        if direction == "OUT" and len(frame) == 2586), None)
        if trigger is None:
            continue
        report = next((i for i in range(trigger + 1, len(events))
                       if events[i][0] == "OUT" and len(events[i][1]) == 282), None)
        if report is None:
            continue
        replies = [frame for direction, frame in events[report + 1:]
                   if direction == "IN"][:4]
        if [len(frame) for frame in replies] == [18, 18, 181, 11]:
            return replies
    raise ValueError("Capture ended before the half-time reply")


def timed_match_rows(path, port):
    rows = []
    pattern = re.compile(r"(\d+\.\d+) \[" + str(port
                        ) + r" (C>S|S>C)\] (\d+)B ([0-9a-f]+)")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = pattern.fullmatch(line)
        if match:
            seconds, direction, size, text = match.groups()
            data = bytes.fromhex(text)
            if len(data) != int(size):
                raise ValueError("Match capture byte count mismatch")
            rows.append((float(seconds), "OUT" if direction == "C>S" else "IN", data))
    return rows


def match_replay(path, port=18020):
    """Return (handshake, stream) for the captured match channel.

    The first four exchanges are the channel login. Requests are matched only by
    frame size because the local client encrypts different payloads. The rest of
    the server stream is paced by the client's 5-byte heartbeat frames, so the
    local match sees the captured bot/state frames on the original timeline.
    """
    timed_rows = timed_match_rows(path, port)
    rows = match_rows(path, port)
    if not rows:
        raise ValueError(f"No {port} match capture")
    groups = exchanges(rows, port)
    if len(groups) < len(MATCH_HANDSHAKE_SHAPE):
        raise ValueError("Match handshake capture is incomplete")
    handshake = []
    shape = MATCH_HANDSHAKE_SHAPE
    if len(groups) >= 4:
        probe = []
        for request, reply in groups[:4]:
            rb = bytearray(reply)
            probe.append(tuple(len(frame) for frame in pop_channel_frames(rb)))
        if probe == list(OLD_MATCH_HANDSHAKE_SHAPE[i][1] for i in range(4)):
            shape = OLD_MATCH_HANDSHAKE_SHAPE
    for step, (group, (expected, reply_size)) in enumerate(zip(groups, shape)):
        request, reply = group
        buffer = bytearray(request)
        lengths = tuple(len(frame) for frame in pop_channel_frames(buffer))
        reply_buffer = bytearray(reply)
        reply_lengths = tuple(len(frame) for frame in pop_channel_frames(reply_buffer))
        request_matches = lengths == expected
        if step == 2:
            request_matches = sorted(lengths) == sorted(expected)
        elif step == 3:
            request_matches = tuple(n for n in lengths if n != 5) == (56,)
        if not request_matches or buffer or reply_lengths != reply_size or reply_buffer:
            raise ValueError(f"Match handshake shape changed: {lengths} / {len(reply)}")
        handshake.append((lengths, reply))

    # Rebuild server-frame timing from capture record timestamps.
    cbuf = bytearray()
    sbuf = bytearray()
    schedule = []
    capture_start = None
    for timestamp, direction, data in timed_rows:
        if capture_start is None:
            capture_start = timestamp
        if direction == "OUT":
            cbuf.extend(data)
            pop_channel_frames(cbuf)
        else:
            sbuf.extend(data)
            for frame in pop_channel_frames(sbuf):
                schedule.append((max(0.0, timestamp - capture_start), frame))
    if not timed_rows:
        cbuf.clear()
        sbuf.clear()
        heartbeats = 0
        for direction, _, data in rows:
            if direction == "OUT":
                cbuf.extend(data)
                for frame in pop_channel_frames(cbuf):
                    if is_heartbeat(frame):
                        heartbeats += 1
            else:
                sbuf.extend(data)
                for frame in pop_channel_frames(sbuf):
                    schedule.append((heartbeats * 0.5, frame))
    if cbuf or sbuf:
        raise ValueError("Incomplete 18020 frame in capture")

    handshake_frames = []
    for _, reply in handshake:
        buffer = bytearray(reply)
        handshake_frames.extend(pop_channel_frames(buffer))
        if buffer:
            raise ValueError("Incomplete match handshake reply")
    if [frame for _, frame in schedule[:len(handshake_frames)]] != handshake_frames:
        raise ValueError("Match handshake reply is not the stream prefix")
    if timed_rows and schedule:
        handshake_end = schedule[len(handshake_frames) - 1][0]
        schedule = [(max(0.0, when - handshake_end), frame)
                    for when, frame in schedule[len(handshake_frames):]]
    else:
        schedule = schedule[len(handshake_frames):]
    # Recv batches are not packet timing: spread each batch across the observed
    # gap to the next batch so snapshots do not arrive as a single burst.
    spread = []
    index = 0
    while index < len(schedule):
        end = index + 1
        when = schedule[index][0]
        while end < len(schedule) and schedule[end][0] == when:
            end += 1
        next_when = schedule[end][0] if end < len(schedule) else when + 0.5
        batch = schedule[index:end]
        step = min(0.05, max(0.001, (next_when - when) / len(batch)))
        spread.extend((when + n * step, frame) for n, (_, frame) in enumerate(batch))
        index = end
    return handshake, spread


def decrypt_envelope(frame, key):
    """Decrypt one ProudNet AES envelope; None when the frame is not one."""
    if len(frame) < 4:
        return None
    header = 3 + frame[2]
    body = frame[header:]
    if len(body) < 4 or body[:2] != b"\x25\x01":
        return None
    width = body[2]
    if width not in (1, 2, 4) or len(body) < 3 + width:
        raise ValueError("Unsupported encrypted envelope length")
    size = int.from_bytes(body[3:3 + width], "little")
    ciphertext = body[3 + width:]
    if size != len(ciphertext) or size % 16:
        raise ValueError("Invalid AES envelope size")
    worker = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return worker.update(ciphertext) + worker.finalize()


def server_progress(frame):
    """Return the loading percentage a captured server frame echoes."""
    if len(frame) != 27:
        return None
    value = struct.unpack_from("<f", frame, 11)[0]
    return value if 0.0 <= value <= 100.0 else None


def client_progress(frame, key):
    """Return the loading percentage a captured client frame reports."""
    if not key or len(frame) != 56:
        return None
    try:
        plain = decrypt_envelope(frame, key)
    except (ValueError, TypeError):
        return None
    if not plain or len(plain) < 19 or plain[2:5] != b"\x02\x01\x19":
        return None
    value = struct.unpack_from("<f", plain, 15)[0]
    return value if 0.0 <= value <= 100.0 else None


def is_time_sync(frame):
    return len(frame) == 21 and frame[4] == 0x1D


def time_sync_reply(client_clock, server_clock):
    # 0x1d echoes the client's 0x1b clock and appends the server clock.
    return b"\x13\x57\x01\x11\x1d" + client_clock + struct.pack("<d", server_clock)


def handle_match(conn, handshake, stream, emit, deadline=None, key=None,
                 halftime=None):
    buffer = bytearray()
    step = 0
    seen = set()
    sent = 0
    stream_start = None
    # Time-sync replies must echo the local client, not the captured clock.
    stream = [(when, frame) for when, frame in stream if not is_time_sync(frame)]
    start_index = next((i for i, (_, frame) in enumerate(stream)
                        if len(frame) == 229), len(stream))
    start_sent = False
    post_start = None
    sent_post = 0
    client_percent = None
    ready_at = None
    base_server = next((struct.unpack_from("<d", reply, 13)[0]
                        for _, reply in handshake
                        if len(reply) == 42 and is_time_sync(reply[:21])), 0.0)
    client_clock = None
    rx = {}
    halftime_sent = False

    def send_due():
        nonlocal sent, start_sent, post_start, sent_post
        if stream_start is None:
            return
        elapsed = time.monotonic() - stream_start
        if start_index >= len(stream):
            while sent < len(stream) and stream[sent][0] <= elapsed:
                conn.sendall(stream[sent][1])
                emit(f"match stream frame={sent} elapsed={elapsed:.3f} "
                     f"bytes={len(stream[sent][1])}")
                sent += 1
            return
        if not start_sent:
            while sent < start_index:
                when = stream[sent][0]
                echoed = server_progress(stream[sent][1])
                if echoed is not None and client_percent is not None:
                    due = client_percent + 0.5 >= echoed
                else:
                    due = when <= elapsed
                if not due:
                    break
                conn.sendall(stream[sent][1])
                emit(f"match stream frame={sent} elapsed={elapsed:.3f} "
                     f"bytes={len(stream[sent][1])}")
                sent += 1
            # Live server sent start 2.36 s after the client's 100% report.
            ready = ready_at is not None and time.monotonic() - ready_at >= 2.36
            fallback = client_percent is None and elapsed >= stream[start_index][0] + 5
            if not ready and not fallback:
                return
            if fallback:
                emit("match start fallback: no client loading report")
            conn.sendall(stream[start_index][1])
            emit(f"match start client_percent="
                 f"{client_percent if client_percent is not None else 'unknown'}")
            start_sent = True
            post_start = time.monotonic()
            sent_post = start_index + 1
            sent = len(stream)
        if post_start is None:
            return
        elapsed = time.monotonic() - post_start
        while sent_post < len(stream):
            when = stream[sent_post][0] - stream[start_index][0]
            if when > elapsed:
                break
            conn.sendall(stream[sent_post][1])
            emit(f"match stream frame={sent_post} elapsed={elapsed:.3f} "
                 f"bytes={len(stream[sent_post][1])}")
            sent_post += 1
            sent = sent_post

    with conn:
        conn.settimeout(0.2)
        try:
            while deadline is None or time.monotonic() < deadline:
                if deadline is not None:
                    conn.settimeout(max(0.01, min(0.2, deadline - time.monotonic())))
                try:
                    data = conn.recv(65536)
                except socket.timeout:
                    send_due()
                    continue
                if not data:
                    return
                buffer.extend(data)
                for frame in pop_channel_frames(buffer):
                    size = len(frame)
                    progress = client_progress(frame, key)
                    if progress is not None:
                        client_percent = progress
                        if progress >= 99.99 and ready_at is None:
                            ready_at = time.monotonic()
                            emit("match client loaded 100%")
                        emit(f"match client progress={progress:.2f}")
                    if size == 21 and frame[4] == 0x1B:
                        client_clock = frame[5:13]
                    if size == 282:
                        emit(f"HALFTIME_REPORT step={step} reply_available={bool(halftime)} already_sent={halftime_sent} hex={frame.hex()}")
                    if size == 282 and halftime and not halftime_sent:
                        for reply in halftime:
                            emit(f"HALFTIME_REPLY hex={reply.hex()}")
                            conn.sendall(reply)
                        halftime_sent = True
                        emit(f"match halftime response frames={len(halftime)}")
                    if step == 0 and size == 9:
                        conn.sendall(handshake[0][1])
                        emit("match handshake step=0 response bytes=210")
                        step = 1
                    elif step == 1 and size == 219:
                        conn.sendall(handshake[1][1])
                        emit("match handshake step=1 response bytes=68")
                        step = 2
                    elif step == 2 and size in (21, 5, 8):
                        seen.add(size)
                        if seen >= {21, 5, 8}:
                            reply = handshake[2][1]
                            if (client_clock and len(reply) == 42
                                    and is_time_sync(reply[:21])):
                                reply = reply[:5] + client_clock + reply[13:]
                            conn.sendall(reply)
                            emit("match handshake step=2 response bytes=42")
                            seen.clear()
                            step = 3
                    elif size == 21 and frame[4] == 0x1B and step > 2 and client_clock:
                        elapsed = (time.monotonic() - stream_start
                                   if stream_start is not None else 0.0)
                        conn.sendall(time_sync_reply(client_clock,
                                                     base_server + elapsed))
                        emit("match time sync echo client_clock="
                             f"{struct.unpack_from('<d', client_clock)[0]:.2f}")
                    elif step == 3 and size == 56:
                        conn.sendall(handshake[3][1])
                        emit("match handshake step=3 response bytes=386")
                        step = 4
                        stream_start = time.monotonic()
                    frame_kind = (size, frame[4])
                    if frame_kind not in rx:
                        rx[frame_kind] = 0
                        emit(f"match rx new frame bytes={size} msg=0x{frame[4]:02x} "
                             f"hex={frame.hex()}")
                    rx[frame_kind] += 1
                    if step >= len(handshake):
                        send_due()
            final_sent = sent_post if start_sent else sent
            emit(f"match end stream_sent={final_sent}/{len(stream)}")
        except (OSError, ValueError) as exc:
            emit(f"match STOP {type(exc).__name__}: {exc}")


def duration_room_reply(frame, template):
    """Echo only the observed room duration field; never copy request tail data."""
    from inspect_shop_capture import decode_reply
    from card_patch import encode_reply
    if len(frame) != 285:
        return None
    request = decode_reply(frame)
    original = decode_reply(template)
    # shortcut: only the captured room layout is supported; other layouts need evidence.
    if (len(request) != 256 or len(original) != 215
            or request[8:16] != original[7:15]
            or request[209:214] != original[208:213]
            or request[214] not in (3, 6, 9)):
        return None
    patched = bytearray(original)
    patched[213] = request[214]
    return encode_reply(bytes(patched), template), request[214]


def handle(conn, groups, emit, deadline=None, channel=False, experimental=False, sync=None,
           room=None, manual_room=False):
    buffer = bytearray()
    step = 0
    matched = 0
    synced = False
    room_step = 0
    pending = []
    pending_since = 0.0
    previous_keys = (False, False)
    difficulty_sequence = None
    difficulty_template = None
    with conn:
        conn.settimeout(10)
        try:
            while deadline is None or time.monotonic() < deadline:
                if manual_room and room:
                    keys = room_hotkeys()
                    edges = tuple(now and not before for now,before in zip(keys,previous_keys))
                    previous_keys = keys
                    target = manual_room_target(room_step,*edges)
                    if target > room_step:
                        for phase in range(room_step,target):
                            if phase == 5 and difficulty_sequence is not None:
                                from difficulty_trial import resequence
                                reply, difficulty_sequence = resequence(room[phase][1], difficulty_sequence)
                                conn.sendall(reply)
                            else:
                                conn.sendall(room[phase][1])
                            emit(f'MANUAL_ROOM phase={phase} response bytes={len(room[phase][1])}')
                        room_step = target
                        pending.clear()
                        pending_since = 0.0
                wait = 10
                if manual_room:
                    wait = 0.1
                if room and room_step < len(room) and pending:
                    wait = 1.5
                if deadline is not None:
                    wait = max(0.01, min(wait, deadline - time.monotonic()))
                conn.settimeout(wait)
                try:
                    data = conn.recv(65536)
                except socket.timeout:
                    # A partial shape does not authorize a room transition.
                    if (room and room_step < len(room) and pending
                            and time.monotonic() - pending_since >= 1.0):
                        emit(f"room step={room_step} partial request expired; no response")
                        pending.clear()
                        pending_since = 0.0
                    if deadline is not None or manual_room:
                        continue
                    raise
                if not data:
                    return
                buffer.extend(data)
                for frame in (pop_channel_frames(buffer) if channel else pop_frames(buffer)):
                    if step >= len(groups):
                        if channel and experimental:
                            control_reply = captured_control_reply(frame)
                            if control_reply is not None:
                                conn.sendall(control_reply)
                                emit("response captured exact control pair bytes=15")
                                continue
                        if channel and experimental and sync and not synced:
                            request, response = sync
                            if len(frame) == len(request) and frame[:8] == request[:8]:
                                conn.sendall(response)
                                emit(f"EXPERIMENT initial sync response bytes={len(response)}")
                                synced = True
                                continue
                        if room and room_step < len(room):
                            if manual_room and room_step >= 2:
                                emit(f'MANUAL_ROOM waiting for End/PageUp; request bytes={len(frame)}')
                                emit(f'ROOM_SETTINGS_CANDIDATE phase={room_step} bytes={len(frame)} hex={frame.hex()}')
                                if room_step == 5:
                                    from difficulty_trial import difficulty_reply
                                    if difficulty_template is None:
                                        difficulty_template = pop_frames(bytearray(room[4][1]))[0]
                                        difficulty_sequence = (difficulty_template[3] + 1) & 255
                                    result = difficulty_reply(frame, difficulty_template, difficulty_sequence,
                                                              allow_team_selection=True)
                                    if result is not None:
                                        reply, level = result
                                        conn.sendall(reply)
                                        difficulty_template = reply
                                        difficulty_sequence = (difficulty_sequence + 1) & 255
                                        emit(f'ROOM_OPPONENT level={level} response={reply.hex()}')
                                continue
                            expected, reply = room[room_step]
                            pending.append(len(frame))
                            if not pending_since:
                                pending_since = time.monotonic()
                            if tuple(pending) == expected:
                                conn.sendall(reply)
                                emit(f"room step={room_step} frames={len(pending)} response bytes={len(reply)}")
                                room_step += 1
                                pending.clear()
                                pending_since = 0.0
                                continue
                            if tuple(pending) == expected[:len(pending)]:
                                emit(f"room step={room_step} partial frames={pending}")
                                continue
                            pending.clear()
                            pending_since = 0.0
                        emit(f"WAIT capture exhausted; request bytes={len(frame)} header={frame[:9].hex()}; no response")
                        if not channel:
                            emit(f"UNHANDLED request={frame.hex()}")
                        continue
                    expected, reply = groups[step]
                    headers = [expected] if channel else signatures(expected)
                    # Channel session fields are unknown: reject differences rather than guess.
                    matches = (channel_matches(expected, frame, experimental) if channel
                               else frame[:4] == headers[matched])
                    if not matches:
                        if channel:
                            # Preserve local request evidence to distinguish session fields.
                            # Never forward it or accept it merely because its size matches.
                            emit(f"MISMATCH expected={expected.hex()} actual={frame.hex()}")
                        emit(f"STOP step={step} frame={matched} header mismatch")
                        return
                    # shortcut: payloads may contain session-specific values;
                    # validate headers only until their fields are decoded.
                    emit(f"request step={step} frame={matched} bytes={len(frame)}")
                    if channel and expected != frame:
                        import hashlib
                        emit(f"EXPERIMENT opaque auth replay; actual_sha256={hashlib.sha256(frame).hexdigest()}")
                    matched += 1
                    if matched == len(headers):
                        conn.sendall(reply)
                        emit(f"response step={step} bytes={len(reply)}")
                        step += 1
                        matched = 0
        except (OSError, ValueError) as exc:
            if buffer[:4] in (b"GET ", b"POST", b"HEAD", b"OPTI"):
                emit("STOP ValueError: non-game HTTP probe")
                return
            if buffer[:1] and buffer[:1] != b"\x32":
                emit(f"STOP unparsed bytes={bytes(buffer[:32]).hex()}")
            emit(f"STOP {type(exc).__name__}: {exc}")


def handle_lobby(conn, stream, emit, deadline=None):
    """Send the captured 8001 lobby stream after the client's first request."""
    buffer = bytearray()
    sent = False
    with conn:
        conn.settimeout(10)
        try:
            while deadline is None or time.monotonic() < deadline:
                wait = 10
                if deadline is not None:
                    wait = max(0.01, min(wait, deadline - time.monotonic()))
                conn.settimeout(wait)
                try:
                    data = conn.recv(65536)
                except socket.timeout:
                    if deadline is None:
                        raise
                    continue
                if not data:
                    return
                buffer.extend(data)
                frames = pop_frames(buffer)
                if not sent and frames:
                    conn.sendall(stream)
                    emit(f"lobby stream bytes={len(stream)} "
                         f"trigger bytes={len(frames[0])}")
                    sent = True
                for frame in frames:
                    emit(f"lobby request bytes={len(frame)}")
        except (OSError, ValueError) as exc:
            if buffer[:4] in (b"GET ", b"POST", b"HEAD", b"OPTI"):
                emit("STOP ValueError: non-game HTTP probe")
                return
            if buffer[:1] and buffer[:1] != b"\x32":
                emit(f"STOP unparsed bytes={bytes(buffer[:32]).hex()}")
            emit(f"STOP {type(exc).__name__}: {exc}")


def handle_channel(conn, setup, trigger, tail, control, emit, deadline=None,
                   experimental=False):
    buffer = bytearray()
    pending = []
    step = 0
    heartbeats = 0
    sent_world = False
    with conn:
        conn.settimeout(0.2)
        try:
            while deadline is None or time.monotonic() < deadline:
                if deadline is not None:
                    conn.settimeout(max(0.01, min(0.2, deadline - time.monotonic())))
                try:
                    data = conn.recv(65536)
                except socket.timeout:
                    continue
                if not data:
                    return
                buffer.extend(data)
                for frame in pop_channel_frames(buffer):
                    if is_heartbeat(frame):
                        heartbeats += 1
                        continue
                    if step < len(setup):
                        expected, reply = setup[step]
                        expected = tuple(item for item in expected if not is_heartbeat(item))
                        pending.append(frame)
                        sizes = tuple(len(item) for item in pending)
                        wanted = tuple(len(item) for item in expected)
                        if sizes == wanted and channel_group_matches(expected, pending,
                                                                      experimental):
                            conn.sendall(reply)
                            emit(f"channel setup step={step} frames={len(pending)} "
                                 f"response bytes={len(reply)}")
                            step += 1
                            pending.clear()
                            continue
                        if wanted[:len(sizes)] == sizes:
                            emit(f"channel setup step={step} partial frames={list(sizes)}")
                            continue
                        emit(f"channel STOP setup step={step} expected={list(wanted)} "
                             f"actual={list(sizes)}")
                        return
                    if not sent_world:
                        expected = tuple(item for item in trigger if not is_heartbeat(item))
                        pending.append(frame)
                        sizes = tuple(len(item) for item in pending)
                        wanted = tuple(len(item) for item in expected)
                        if sizes == wanted and channel_group_matches(expected, pending,
                                                                      experimental):
                            emit(f"channel trigger frames={len(pending)} world_frames={len(tail)} "
                                 f"world_bytes={sum(len(item) for item in tail)}")
                            # The world burst is large; do not let the read timeout
                            # abort it while the client is busy loading the scene.
                            conn.settimeout(10)
                            for index, server_frame in enumerate(tail):
                                conn.sendall(server_frame)
                                if index % 8 == 7:
                                    time.sleep(0.002)
                            sent_world = True
                            pending.clear()
                            continue
                        if wanted[:len(sizes)] == sizes:
                            emit(f"channel trigger partial frames={list(sizes)}")
                            continue
                        emit(f"channel STOP trigger expected={list(wanted)} "
                             f"actual={list(sizes)}")
                        return
                    if (control is not None and len(frame) == 15
                            and frame[:5] == control[:5]):
                        conn.sendall(control)
                        emit("channel control response bytes=15")
                    else:
                        emit(f"channel post-world request bytes={len(frame)} "
                             f"header={frame[:9].hex()}")
            emit(f"channel end heartbeats={heartbeats} world={sent_world}")
        except (OSError, ValueError) as exc:
            emit(f"channel STOP {type(exc).__name__}: {exc}")


def self_test():
    a = bytes.fromhex("32030000616263")
    b = bytes.fromhex("320100017a")
    for cut in range(len(a + b) + 1):
        buffer = bytearray((a + b)[:cut])
        frames = pop_frames(buffer)
        buffer.extend((a + b)[cut:])
        frames.extend(pop_frames(buffer))
        assert frames == [a, b] and not buffer
    rows = [("OUT", 1, a), ("OUT", 1, b), ("IN", 1, b"x"),
            ("IN", 2, b"ignored"), ("IN", 1, b"y")]
    assert exchanges(rows, 1) == [(a + b, b"xy")]
    left, right = socket.socketpair()
    messages = []
    worker = threading.Thread(target=handle, args=(left, [(a + b, b"ok")], messages.append))
    worker.start()
    with right:
        right.settimeout(2)
        right.sendall(a[:2])
        right.sendall(a[2:] + b)
        assert right.recv(2) == b"ok"
    worker.join(timeout=2)
    assert not worker.is_alive()
    left, right = socket.socketpair()
    messages = []
    room = [((28, 28, 28, 285), b"room-reply")]
    worker = threading.Thread(target=handle, args=(left, [], messages.append),
                              kwargs={"room": room})
    worker.start()
    with right:
        right.settimeout(2)
        for index in range(3):
            right.sendall(b"2" + (24).to_bytes(3, "little") + bytes([index]) * 24)
        try:
            unexpected = right.recv(10)
        except socket.timeout:
            pass
        else:
            assert unexpected == b'', f'Unexpected room transition: {unexpected!r}'
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert any("partial request expired" in message for message in messages), messages
    print("PASS: partial request cannot trigger a room transition")
    print("PASS: split/coalesced framing, socket separation, actual local replay")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--seconds", type=int, default=120)
    parser.add_argument("--experimental-channel", action="store_true")
    parser.add_argument("--diagnose-auth", action="store_true",
                        help="local diagnosis only; old fixture, not playable world replay")
    parser.add_argument("--capture", default=None,
                        help="capture file; defaults to latest_capture.txt")
    parser.add_argument("--lobby-card", action="store_true",
                        help="serve only the captured 8001 lobby stream; no match port")
    parser.add_argument('--manual-room',action='store_true',help='Experimental foreground End/PageUp room control')
    parser.add_argument("--session-key", default=None,
                        help="expected forced key in the capture; 32 hex chars")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not 0 <= args.seconds <= 600:
        parser.error("--seconds must be between 0 and 600 (0 = unlimited)")
    capture = ROOM_CAPTURE if args.diagnose_auth else Path(args.capture) if args.capture else latest_capture()
    if capture is None:
        print("No latest_capture.txt; run CAPTURE_ROOM.cmd first.", flush=True)
        return 2
    if not args.diagnose_auth and not args.capture:
        candidates = [capture, *sorted(HERE.glob("capture-*.log"), reverse=True)]
        for candidate in dict.fromkeys(candidates):
            try:
                if args.lobby_card:
                    lobby_stream(candidate)
                else:
                    match_port(candidate)
                    room_phases(candidate)
                channel_plan(candidate)
                if forced_session_key(candidate):
                    capture = candidate
                    break
            except (OSError, ValueError):
                continue
    forced = forced_session_key(capture)
    if forced is None and not args.diagnose_auth:
        print(f"Capture has no forced session key: {capture}", flush=True)
        print("Run CAPTURE_ROOM.cmd first; old captures cannot be decrypted offline.", flush=True)
        return 2
    if args.session_key and forced != args.session_key.strip().lower() and not args.diagnose_auth:
        print(f"Capture key {forced} != offline key {args.session_key}; replay refused.", flush=True)
        return 2
    rows = records(HERE / "game.log")
    # The room and match channels come entirely from one live session so server
    # sequence numbers stay continuous from login through the match handshake.
    plans = {8000: exchanges(rows, 2756), 8001: [], 18030: []}
    room = None
    lobby = None
    handshake = stream = halftime = None
    if args.lobby_card:
        match_port_value = None
        lobby = lobby_stream(capture)
    else:
        match_port_value = match_port(capture)
        plans[match_port_value] = []
        room = room_phases(capture)
        handshake, stream = match_replay(capture, match_port_value)
    setup, trigger, tail, control = channel_plan(capture)
    if not args.lobby_card:
        recent_capture = HERE / 'capture-20261104-065715.log'
        if not recent_capture.exists():
            recent_capture = latest_capture()
        if recent_capture:
            try:
                halftime = halftime_responses(recent_capture)
            except (OSError, ValueError):
                pass
    for port, groups in plans.items():
        if not groups and port not in (8001, match_port_value, 18030):
            raise ValueError(f"No recorded exchanges for {port}")
        if port == 8000:
            for request, _ in groups:
                signatures(request)
    listeners = []
    deadline = time.monotonic() + args.seconds if args.seconds else float('inf')
    logpath = HERE / f"offline-{time.time_ns()}.log"
    lock = threading.Lock()
    with logpath.open("x", encoding="utf-8") as out:
        def emit(message):
            with lock:
                out.write(f"{time.monotonic():.6f} {message}\n")
                out.flush()

        def serve(srv, port):
            while time.monotonic() < deadline:
                try:
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                # Bound workers by remaining run time, so they finish before log closes.
                if port == 8001 and lobby is not None:
                    handle_lobby(conn, lobby,
                                 lambda message: emit(f"[{port}] {message}"), deadline)
                elif port == 18030:
                    handle_channel(conn, setup, trigger, tail, control,
                                   lambda message: emit(f"[{port}] {message}"), deadline,
                                   args.experimental_channel)
                elif port == match_port_value:
                    handle_match(conn, handshake, stream,
                                 lambda message: emit(f"[{port}] {message}"), deadline,
                                 bytes.fromhex(forced) if forced else None, halftime)
                else:
                    handle(conn, plans[port], lambda message: emit(f"[{port}] {message}"),
                            deadline, room=room if port == 8001 else None,
                            manual_room=args.manual_room and port == 8001)

        threads = []
        try:
            for port in plans:
                srv = socket.socket()
                listeners.append(srv)
                srv.bind(("127.0.0.1", port))
                srv.listen(2)
                srv.settimeout(0.5)
                thread = threading.Thread(target=serve, args=(srv, port))
                thread.start()
                threads.append(thread)
            print(f"Local-only replay ready; "
                  f"{'lobby-only' if match_port_value is None else f'match_port={match_port_value}'}; "
                  f"18030_world_frames={len(tail)}; log: {logpath}", flush=True)
            print(f"Capture: {capture}", flush=True)
            print(f"HALFTIME_DIAGNOSTIC source={latest_capture()} replies={len(halftime or [])}", flush=True)
            while time.monotonic() < deadline:
                time.sleep(0.2)
        finally:
            for srv in listeners:
                srv.close()
            for thread in threads:
                thread.join()


if __name__ == "__main__":
    raise SystemExit(main())
