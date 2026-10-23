# AI Security Trainer (Cloudflare Worker starter)

This project is a separate Cloudflare Worker application.

## Included
- Mobile-friendly dashboard
- Local-only model file picker (does not upload or run model files)
- JSONL dataset format inspection
- Basic static code pattern checks through a Worker API

## Important limitations
This starter does not train model weights and does not persist uploaded files. Model fine-tuning requires a compatible training runtime/model format. Do not upload sensitive files until authentication and private storage are implemented. The static checks are not a full security audit.

## Deploy options
Cloudflare's dashboard does not generally accept this ZIP as a one-click Worker source import. Use one of these routes:
1. Put these files in a GitHub repository and connect it to Cloudflare Workers Builds; or
2. Use Wrangler from a computer/terminal with `npx wrangler deploy`.

On iPhone, the GitHub + Cloudflare dashboard route is usually easiest, but it still requires creating the files in the repository.
