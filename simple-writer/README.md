# simple-writer

Test program that writes custom labels. Used with `context-reader` to verify TLS reading works across different linking scenarios. 

## Variants
We have variants that exercise the combinations of **linking mode of the TLS library** and **libc variant**. These call run on both aarch64 and arm64, and you can use the lima VM templates in the root of the repository to test with either.

| Binary | Labels | libc | Notes |
|--------|--------|------|---------------------|
| `simple-writer-static-musl` | static | musl | Will always land in static TLS block |
| `simple-writer-static-glibc` | static | glibc | Will always land in static TLS block |
| `simple-writer-dynamic-glibc` | dynamic | glibc | Will always land in static TLS block (because we compile the lib with TLSDESC) |
| `simple-writer-dlopen-glibc` | dlopen | glibc | _Will generally_ land in static TLS block due to reserved TL storage |
| `simple-writer-exhaust-static-tls` | dlopen | glibc | Uses another library to exhaust static TL block buffer before loading labels library; labels library will be forced into DTV |

## Files

- `simple-writer.c` - Main program (static/dynamic linking)
- `simple-writer-dlopen.c` - dlopen variant
- `simple-writer-exhaust-static-tls.c` - Loads filler libs first to force DTV path
- `process_context.c` - Writes process-context for V2 key table

## Build

```bash
make simple-writer-dynamic-glibc   # or any variant
```

Requires `../custom-labels/libcustomlabels.{a,so}` to be built first.
