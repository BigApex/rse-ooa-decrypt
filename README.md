# Respawn's Source Engine `.ooa` decrypt tool

This project was made to eliminate the need to distribute binary blobs, which might give some trouble if used in fan made projects.

## Usage

```bash
rse_ooa_decrypt.exe packed.exe [.dlf file]
```

This tool will automatically find correct `.dlf` file in `%ProgramData%\Electronic Arts\EA Services\License` if you are on Windows and in the current directory.

## Supported versions

 * Retail Apex, BFV (`5.02.04.66`)
 * Titanfall 2 (`5.00.01.35`)
 * Skate CPT (`5.02.08.75`)


## Non-Goals

 * Make this as small of a binary as possible
   * This usually trips over most Anti-Virus solutions