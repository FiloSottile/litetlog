#!/usr/bin/python3
"""
Derived from intoto.py by Lukas Puehringer <lukas.puehringer@nyu.edu>.
https://github.com/in-toto/apt-transport-in-toto/blob/81fd97/intoto.py

    Copyright 2018 New York University
    Copyright 2024 Filippo Valsorda

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

Install this script as /usr/lib/apt/methods/tlog and make it executable.
Change the apt sources.list to use tlog:// instead of https://.
Requires the python3-requests package, and spicy in $PATH.
"""

import os
import sys
import signal
import select
import threading
import logging
import logging.handlers
import requests
import queue as Queue
import subprocess

# Configure base logger with lowest log level (i.e. log all messages) and
# finetune the actual log levels on handlers
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# A file handler for debugging purposes
LOG_FILE = "/var/log/apt/tlog.log"
LOG_HANDLER_FILE = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=100000)
LOG_HANDLER_FILE.setLevel(logging.DEBUG)
logger.addHandler(LOG_HANDLER_FILE)

# A stream handler (stderr)
LOG_HANDLER_STDERR = logging.StreamHandler()
LOG_HANDLER_STDERR.setLevel(logging.INFO)
logger.addHandler(LOG_HANDLER_STDERR)

APT_METHOD_HTTPS = os.path.join(os.path.dirname(sys.argv[0]), "https")

# Global interrupted boolean. Apt may send SIGINT if it is done with its work.
# Upon reception we set INTERRUPTED to true, which may be used to gracefully
# terminate.
INTERRUPTED = False


# TODO: Maybe we can replace the signal handler with a KeyboardInterrupt
# try/except block in the main loop, for better readability.
def signal_handler(*junk):
    # Set global INTERRUPTED flag telling worker threads to terminate
    logger.debug("Received SIGINT, setting global INTERRUPTED true")
    global INTERRUPTED
    INTERRUPTED = True


# Global BROKENPIPE flag should be set to true, if a `write` or `flush` on a
# stream raises a BrokenPipeError, to gracefully terminate reader threads.
BROKENPIPE = False

# APT Method Interface Message definition
# The first line of each message is called the message header. The first 3
# digits (called the Status Code) have the usual meaning found in the http
# protocol. 1xx is informational, 2xx is successful and 4xx is failure. The 6xx
# series is used to specify things sent to the method. After the status code is
# an informational string provided for visual debugging
# Only the 6xx series of status codes is sent TO the method. Furthermore the
# method may not emit status codes in the 6xx range. The Codes 402 and 403
# require that the method continue reading all other 6xx codes until the proper
# 602/603 code is received. This means the method must be capable of handling
# an unlimited number of 600 messages.

# Message types by their status code.
CAPABILITES = 100
LOG = 101
STATUS = 102
URI_START = 200
URI_DONE = 201
URI_FAILURE = 400
GENERAL_FAILURE = 401
AUTH_REQUIRED = 402
MEDIA_FAILURE = 403
URI_ACQUIRE = 600
CONFIGURATION = 601
AUTH_CREDENTIALS = 602
MEDIA_CHANGED = 603

MESSAGE_TYPE = {
    # Method capabilities
    CAPABILITES: "Capabilities",
    # General Logging
    LOG: "Log",
    # Inter-URI status reporting (logging progress)
    STATUS: "Status",
    # URI is starting acquire
    URI_START: "URI Start",
    # URI is finished acquire
    URI_DONE: "URI Done",
    # URI has failed to acquire
    URI_FAILURE: "URI Failure",
    # Method did not like something sent to it
    GENERAL_FAILURE: "General Failure",
    # Method requires authorization to access the URI. Authorization is User/Pass
    AUTH_REQUIRED: "Authorization Required",
    # Method requires a media change
    MEDIA_FAILURE: "Media Failure",
    # Request a URI be acquired
    URI_ACQUIRE: "URI Acquire",
    # Sends the configuration space
    CONFIGURATION: "Configuration",
    # Response to the 402 message
    AUTH_CREDENTIALS: "Authorization Credentials",
    # Response to the 403 message
    MEDIA_CHANGED: "Media Changed",
}


def deserialize_one(message_str):
    """Parse raw message string as it may be read from stdin and return a
    dictionary that contains message header status code and info and an optional
    fields dictionary of additional headers and their values.

    Raise Exception if the message is malformed.

    {
      "code": <status code>,
      "info": "<status info>",
      "fields": [
        ("<header field name>", "<value>"),
      ]
    }

    NOTE: Message field values are NOT deserialized here, e.g. the Last-Modified
    time stamp remains a string and Config-Item remains a string of item=value
    pairs.

    """
    lines = message_str.splitlines()
    if not lines:
        raise Exception("Invalid empty message:\n{}".format(message_str))

    # Deserialize message header
    message_header = lines.pop(0)
    message_header_parts = message_header.split()

    # TODO: Are we too strict about the format (should we not care about info?)
    if len(message_header_parts) < 2:
        raise Exception(
            "Invalid message header: {}, message was:\n{}".format(
                message_header, message_str
            )
        )

    code = None
    try:
        code = int(message_header_parts.pop(0))
    except ValueError:
        pass

    if not code or code not in list(MESSAGE_TYPE.keys()):
        raise Exception(
            "Invalid message header status code: {}, message was:\n{}".format(
                code, message_str
            )
        )

    # TODO: Are we too strict about the format (should we not care about info?)
    info = " ".join(message_header_parts).strip()
    if info != MESSAGE_TYPE[code]:
        raise Exception(
            "Invalid message header info for status code {}:\n{},"
            " message was: {}".format(code, info, message_str)
        )

    # TODO: Should we assert that the last line is a blank line?
    if lines and not lines[-1]:
        lines.pop()

    # Deserialize header fields
    header_fields = []
    for line in lines:

        header_field_parts = line.split(":")

        if len(header_field_parts) < 2:
            raise Exception(
                "Invalid header field: {}, message was:\n{}".format(line, message_str)
            )

        field_name = header_field_parts.pop(0).strip()

        field_value = ":".join(header_field_parts).strip()
        header_fields.append((field_name, field_value))

    # Construct message data
    message_data = {"code": code, "info": info}
    if header_fields:
        message_data["fields"] = header_fields

    return message_data


def serialize_one(message_data):
    """Create a message string that may be written to stdout. Message data
    is expected to have the following format:
    {
      "code": <status code>,
      "info": "<status info>",
      "fields": [
        ("<header field name>", "<value>"),
      ]
    }

    """
    message_str = ""

    # Code must be present
    code = message_data["code"]
    # Convenience (if info not present, info for code is used )
    info = message_data.get("info") or MESSAGE_TYPE[code]

    # Add message header
    message_str += "{} {}\n".format(code, info)

    # Add message header fields and values (must be list of tuples)
    for field_name, field_value in message_data.get("fields", []):
        message_str += "{}: {}\n".format(field_name, field_value)

    # Blank line to mark end of message
    message_str += "\n"

    return message_str


def read_one(stream):
    """Read one apt related message from the passed stream, e.g. sys.stdin for
    messages from apt, or subprocess.stdout for messages from a transport that we
    open in a subprocess. The end of a message (EOM) is denoted by a blank line
    ("\n") and end of file (EOF) is denoted by an empty line. Returns either a
    message including a trailing blank line or None on EOF.

    """
    message_str = ""
    # Read from stream until we get a SIGINT/BROKENPIPE, or reach EOF (see below)
    # TODO: Do we need exception handling for the case where we select/read from
    # a stream that was closed? If so, we should do it in the main loop for
    # better readability.
    while not (INTERRUPTED or BROKENPIPE):  # pragma: no branch
        # Only read if there is data on the stream (non-blocking)
        if not select.select([stream], [], [], 0)[0]:
            continue

        # Read one byte from the stream
        one = os.read(stream.fileno(), 1).decode()

        # Break on EOF
        if not one:
            break

        # If we read something append it to the message string
        message_str += one

        # Break on EOM (and return message below)
        if len(message_str) >= 2 and message_str[-2:] == "\n\n":
            break

    # Return a message if there is one, otherwise return None
    if message_str:
        return message_str

    return None


def write_one(message_str, stream):
    """Write the passed message to the passed stream."""
    try:
        stream.write(message_str)
        stream.flush()

    except BrokenPipeError:
        # TODO: Move exception handling to main loop for better readability
        global BROKENPIPE
        BROKENPIPE = True
        logger.debug(
            "BrokenPipeError while writing '{}' to '{}'.".format(message_str, stream)
        )
        # Python flushes standard streams on exit; redirect remaining output
        # to devnull to avoid another BrokenPipeError at shutdown
        # See https://docs.python.org/3/library/signal.html#note-on-sigpipe
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())


def notify_apt(code, message_text, uri):
    # Escape LF and CR characters in message bodies to not break the protocol
    message_text = message_text.replace("\n", "\\n").replace("\r", "\\r")
    # NOTE: The apt method interface spec references RFC822, which doesn't allow
    # LF or CR in the message body, except if followed by a LWSP-char (i.e. SPACE
    # or HTAB, for "folding" of long lines). But apt does not seem to support
    # folding, and splits lines only at LF. To be safe we escape LF and CR.
    # See 2.1 Overview in www.fifi.org/doc/libapt-pkg-doc/method.html/ch2.html
    # See "3.1.1. LONG HEADER FIELDS" and  "3.1.2. STRUCTURE OF HEADER FIELDS" in
    # www.ietf.org/rfc/rfc822.txt

    write_one(
        serialize_one(
            {
                "code": code,
                "info": MESSAGE_TYPE[code],
                "fields": [("Message", message_text), ("URI", uri)],
            }
        ),
        sys.stdout,
    )


def read_to_queue(stream, queue):
    """Loop to read messages one at a time from the passed stream until EOF, i.e.
    the returned message is None, and write to the passed queue.

    """
    while True:
        msg = read_one(stream)
        if not msg:
            return None

        queue.put(msg)


def handle(message_data):
    logger.debug("Handling message: {}".format(message_data["code"]))

    if message_data["code"] == CAPABILITES:
        # TODO(filippo): intercept Capabilities messages to avoid future
        # features bypassing verification.
        return True

    elif message_data["code"] == URI_ACQUIRE:
        # TODO(filippo): redirect InRelease file fetches to the tlog server.
        return True

    elif message_data["code"] == URI_DONE:
        # TODO(filippo): catch exceptions, print stack trace to stderr, and
        # notify URI_FAILURE to apt.

        filename = dict(message_data["fields"]).get("Filename", "")
        uri = dict(message_data["fields"]).get("URI", "")
        hit = dict(message_data["fields"]).get("IMS-Hit", "")

        # TODO(filippo): use Target-Type or Index-File from the URI_ACQUIRE.
        if not uri.endswith("/InRelease"):
            return True

        if hit == "true":
            return True

        notify_apt(STATUS, "Fetching InRelease file spicy signature", uri)

        spicy_uri = (
            "https://debian-spicy-signatures.fly.storage.tigris.dev/debian/"
            + uri.split("/dists/")[-1]
            + ".spicy"
        )
        logger.debug("Spicy sig URL: {}".format(spicy_uri))

        r = requests.get(spicy_uri)
        r.raise_for_status()
        with open(filename + ".spicy", "wb") as f:
            f.write(r.content)

        notify_apt(STATUS, "Verifying InRelease file spicy signature", uri)
        subprocess.check_output(
            [
                "spicy",
                "-verify",
                "filippo.io/debian-archive+6c61b70b+Aaw9ASjgICSzfKJDcCqz7l3FtSpKvQYCvaRfdfOiIRun",
                filename,
            ],
            stderr=subprocess.STDOUT,
        )
        logger.debug("Verified {} 🌶️".format(uri.split("/dists/")[-1]))

        # TODO(filippo): use fields from the URI_ACQUIRE.
        base = uri.split("/dists/")[0]
        dist = uri.split("/dists/")[1].split("/")[0]
        print("\r 🌶️    {} {} InRelease.spicy".format(base, dist), file=sys.stderr)

        return True

    else:
        return True


def loop():
    """Main tlog https transport method loop to relay messages between apt and
    the apt https transport method and inject spicy verification upon reception
    of a particular message.

    """
    # Start https transport in a subprocess
    # Messages from the parent process received on sys.stdin are relayed to the
    # subprocess' stdin and vice versa, messages written to the subprocess'
    # stdout are relayed to the parent via sys.stdout.
    https_proc = subprocess.Popen(
        [APT_METHOD_HTTPS],
        stdin=subprocess.PIPE,  # nosec
        stdout=subprocess.PIPE,
        universal_newlines=True,
    )

    # HTTPS transport message reader thread to add messages from the https
    # transport (subprocess) to a corresponding queue.
    https_queue = Queue.Queue()
    https_thread = threading.Thread(
        target=read_to_queue, args=(https_proc.stdout, https_queue)
    )

    # APT message reader thread to add messages from apt (parent process)
    # to a corresponding queue.
    apt_queue = Queue.Queue()
    apt_thread = threading.Thread(target=read_to_queue, args=(sys.stdin, apt_queue))

    # Start reader threads.
    # They will run until they see an EOF on their stream, or the global
    # INTERRUPTED or BROKENPIPE flags are set to true.
    https_thread.start()
    apt_thread.start()

    # Main loop to get messages from queues, i.e. apt queue and https transport
    # queue, and relay them to the corresponding streams, injecting verification.
    while True:
        for name, queue, out in [
            ("apt", apt_queue, https_proc.stdin),
            ("https", https_queue, sys.stdout),
        ]:

            should_relay = True
            try:
                message = queue.get_nowait()
                logger.debug("{} sent message:\n{}".format(name, message))
                message_data = deserialize_one(message)

            except Queue.Empty:
                continue

            # De-serialization error: Skip message handling, but do relay.
            except Exception as e:
                # TODO(filippo): this is insecure, fail closed.
                logger.debug("Cannot handle message, reason is {}".format(e))

            else:
                logger.debug("Handle message")
                should_relay = handle(message_data)

            if should_relay:
                logger.debug("Relay message")
                write_one(message, out)

        # Exit when both threads have terminated (EOF, INTERRUPTED or BROKENPIPE)
        # NOTE: We do not check if there are still messages on the streams or
        # in the queue, assuming that there aren't or we can ignore them if both
        # threads have terminated.
        if not apt_thread.is_alive() and not https_thread.is_alive():
            logger.debug(
                "The worker threads are dead. Long live the worker threads!"
                "Terminating."
            )

            # If INTERRUPTED or BROKENPIPE are true it (likely?) means that apt
            # sent a SIGINT or closed the pipe we were writing to. This means we
            # should exit and tell the http child process to exit too.
            # TODO: Could it be that the http child closed a pipe or sent a SITERM?
            # TODO: Should we behave differently for the two signals?
            if INTERRUPTED or BROKENPIPE:  # pragma: no branch
                logger.debug("Relay SIGINT to http subprocess")
                https_proc.send_signal(signal.SIGINT)

            return


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    loop()
