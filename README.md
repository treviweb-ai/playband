# PlayBand

Free football play designer and wristband maker, by [Trevi Web Co.](https://treviweb.com)

Draw plays for 11-man, 7v7 and 5v5 flag football, save formations, and print wristbands and coach call sheets.

## How it is built

The beta is a single static page: `index.html` holds all markup, styles and script. There is no build step and no server. Plays are stored in the visitor's browser (`localStorage`), with Back up / Restore to a JSON file.

## Run it locally

Open `index.html` in a browser.

## Deploy

Hosted on Cloudflare Pages from the `main` branch.

- Framework preset: None
- Build command: (leave empty)
- Build output directory: `/`

Every push to `main` goes live.

## Feedback

info@treviweb.com
