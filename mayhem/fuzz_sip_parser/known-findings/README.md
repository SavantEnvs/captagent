# fuzz_sip_parser notes

No crash was found in a 60 s four-process fork-mode run. The harness models two properties of how
`protocol_sip.c` calls the parser, and the parser relies on both:

- `parse_sip()` rejects any message whose first byte is not a letter (`isalpha`) before calling
  `parse_message()`; the harness applies the same precondition. Without it `parse_message()` reads one byte
  before the buffer at parser_sip.c:696 for a message starting with `\n` (reproducer bytes `01 0a 10 04`).
- Messages live inside larger capture buffers; the harness NUL-terminates each copy and gives it 64 spare bytes.
  Short header lines make `check_sip_message()` (parser_sip.c:1093) probe a few bytes past the message.
