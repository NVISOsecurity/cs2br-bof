/*
 * CS2BR BOF Patcher - Compatibility Layer by NVISO
 * -------------------------
 * This C file implements a custom badger entrypoint that
 * 	- (optionally) decodes provided base64 input
 * 	- calls the original BOF entrypoint (which is renamed to csentry)
 */

#define CSEP go

/* Forward declarations of the base64 utilities */
size_t b64_decoded_size(char *in);
int b64_isvalidchar(char c);
int b64_decode(char *in, unsigned char *out, size_t outlen);

/* Badger entrypoint */
void coffee(char **argv, int argc, WCHAR **dispatch)
{
    size_t size = 0;
    char *buffer = NULL;

    // Set global dispatch variable to allow CS-wrappers to use the BR API's output methods
    _dispatch = dispatch;

    BadgerDispatch(dispatch, "[cs2br] Starting...\n");

    // Validate input args
    if (argc > 1)
    {
        BadgerDispatch(dispatch, "[cs2br] Expected 0-1 arguments, got %i!\n", argc);
        return;
    }

    if (argc == 1)
    {
        // Decode base64 input
        BadgerDispatch(dispatch, "[cs2br] Determining required buffer size...\n", size);
        size = b64_decoded_size(argv[0]);
        if (size != 0)
        {
            BadgerDispatch(dispatch, "[cs2br] Allocating %lld bytes...\n", size);
            buffer = (char *)BadgerAlloc(size);
            if (!buffer)
            {
                BadgerDispatch(dispatch, "[cs2br] Failed to allocate %lldi bytes; bailing out!\n", size);
                return;
            }
            BadgerMemset(buffer, 0, size);
            BadgerDispatch(dispatch, "[cs2br] Decoding base64 input...\n", size);
            if (!b64_decode(argv[0], (unsigned char *)buffer, size))
            {
                BadgerDispatch(dispatch, "[cs2br] Failed to decode base64 input; bailing out!\n");
                return;
            }
            BadgerDispatch(dispatch, "[cs2br] Decoding done!\n");
        }
        else
        {
            BadgerDispatch(dispatch, "[cs2br] Determined buffer size is zero; bailing out!\n");
            return;
        }
    }

    BadgerDispatch(dispatch, "[cs2br] Invoking entrypoint...\n");
    #ifdef CS2BRBINPATCH
    go(buffer, size);
    #else
    csentry(buffer, size);
    #endif
    BadgerDispatch(dispatch, "[cs2br] Done; exiting!\n");

    if (buffer != NULL)
        BadgerFree((PVOID *)&buffer);
}

/*  Basic implementation of base64 decoding
    based on John Schember's base64 implementation in C
    ref https://nachtimwald.com/2017/11/18/base64-encode-and-decode-in-c/ */
size_t b64_decoded_size(char *in)
{
    size_t len = 0, ret = 0, i = 0;

    if (in == NULL)
        return 0;

    len = BadgerStrlen(in);
    if (len < 2)
        return ret; // Sanity check: base64 encoding a single char results in at least 2 chars (+2 padding)
    if (len > 0)
    {
        ret = len / 4 * 3;

        for (i = len; i-- > 0;)
        {
            if (in[i] == '=')
                ret--;
            else
                break;
        }
    }

    return ret > 0 ? ret : 1;
}

int b64_isvalidchar(char c)
{
    if (c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '+' || c == '/' || c == '=')
        return 1;
    return 0;
}

int b64_decode(char *in, unsigned char *out, size_t outlen)
{
    size_t len, i, j;
    int v;
    int b64invs[] = {62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
                     59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
                     6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                     21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
                     29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
                     43, 44, 45, 46, 47, 48, 49, 50, 51};

    if (in == NULL || out == NULL)
        return 0;

    len = BadgerStrlen(in);
    if (outlen < b64_decoded_size(in) || len % 4 != 0)
        return 0;

    for (i = 0; i < len; i++)
    {
        if (!b64_isvalidchar(in[i]))
            return 0;
    }

    for (i = 0, j = 0; i < len; i += 4, j += 3)
    {
        v = b64invs[in[i] - 43];
        v = (v << 6) | b64invs[in[i + 1] - 43];
        v = in[i + 2] == '=' ? v << 6 : (v << 6) | b64invs[in[i + 2] - 43];
        v = in[i + 3] == '=' ? v << 6 : (v << 6) | b64invs[in[i + 3] - 43];

        out[j] = (v >> 16) & 0xFF;
        if (in[i + 2] != '=')
            out[j + 1] = (v >> 8) & 0xFF;
        if (in[i + 3] != '=')
            out[j + 2] = v & 0xFF;
    }

    return 1;
}