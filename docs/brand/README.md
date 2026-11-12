# Eplix logo

The mark is a moon crossing a gem. The gem is Ethereum, so together they stand for an Ethereum validator. The moon passing in front of it is an eclipse, which is where the name Eplix comes from. It is two flat shapes and nothing else. The client aims to be light and to stay secure by staying simple, and the logo follows the same rule.

This is variant 02 "Broad gem" from the third design round. The gem is squatter than the Ethereum diamond (width to height about 0.85) so it keeps its mass at 16 px.

## Colors

The indigo and amber pair from round 2. The moon and the wordmark take the main color, the gem and the dot on the i take the accent.

| Use | Main (moon, wordmark) | Accent (gem, i dot) |
| --- | --- | --- |
| Light backgrounds | `#1D1B44` indigo | `#D0861C` amber |
| Dark backgrounds | `#E7E4F6` pale lavender | `#F2B84B` light amber |

Round 3 chose the dark values against GitHub's dark background, `#0D1117`. In one color, use the main color of the background's set for both shapes.

## Clear space and minimum size

Leave empty space round the mark at least as wide as the moon's radius: 12 units in the 64-unit symbol box, 9 units in the 48-unit-high lockup. Don't put text or other logos inside it.

The symbol works down to 16 px. Below 32 px use the color version: the gap between moon and gem is under a pixel there, and the two colors keep them apart. Don't set the lockup smaller than 24 px high, or the wordmark strokes drop under 2 px.

## Files

| File | Use |
| --- | --- |
| `eplix-lockup-light.svg`, `eplix-lockup-dark.svg` | Symbol and wordmark in color. README headers, docs, slides. The repo README switches between them with `<picture>`. |
| `eplix-symbol-light.svg`, `eplix-symbol-dark.svg` | Symbol alone in color, where the name is already shown. |
| `eplix-symbol.svg`, `eplix-lockup.svg` | One color, `currentColor`. Inline them in HTML and they take the text color. As an `<img>` they render black. |
| `favicon.svg` | Browser tab icon. Switches to the dark colors when the browser is in dark mode. |
| `eplix-16.png` to `eplix-256.png` | Light colors on a white square. Favicon fallback (16, 32), avatars and app icons (64 to 256). |

The files come from `build.py` in the round 3 design folder, which also draws the PNGs. Don't edit the path data by hand. The symbol paths are the same in every file.
