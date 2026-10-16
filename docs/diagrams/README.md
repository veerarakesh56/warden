# Architecture diagrams

Each `.drawio` file is the source. The `.svg` and `.png` files next to it are exports of it.

| Source | Exports | What it shows |
|---|---|---|
| `architecture-overview.drawio` | `architecture-overview.svg`, `.png` | The whole system on one page, with the numbered path of an incident |
| `architecture-detailed.drawio` | page 1: `architecture-detailed-1.svg`, `.png` · page 2: `architecture-detailed-2.svg`, `.png` | Every component by its real name: the runtime, then identities, environments and outside services |
| `incident-flow.drawio` | `incident-flow.svg`, `.png` | One incident from alarm to signed record, by trust zone, with the safety checks marked S1-S14 |
| `delivery.drawio` | `delivery.svg`, `.png` | Branches, pipelines, the Helios gate and the OIDC deploy roles |

Every diagram says in its footer which commit it was drawn from. The README embeds the PNGs, which are lighter than the SVGs (1.6-4.3 MB, as draw.io adds
an image fallback for every label), and links each one to its SVG. Open pull requests and unmerged branches are
drawn with a dashed yellow outline and labelled as open; nothing planned is drawn as built.

## Edit

1. Open the `.drawio` file in draw.io: the desktop app, or <https://app.diagrams.net> → File → Open from → Device.
2. Change it and save it as an uncompressed `.drawio` file (File → Properties → untick Compressed), so a
   change can be reviewed as a diff.
3. Update the footer's commit if the diagram now shows a later state of the code.

Colours: the five trust zones use WARDEN's brand colours (read #3DB9F5, llm #1A8FE3, core #12C483,
notify #7DF2C4, act #FF7E6B); Lambdas are orange; the font is Helvetica.

## Re-export

With the draw.io desktop app (these files were exported with 31.5.2):

```sh
cd docs/diagrams
DRAWIO="C:/Program Files/draw.io/draw.io.exe"   # or wherever draw.io is installed
for n in architecture-overview incident-flow delivery; do
  "$DRAWIO" -x -f svg --theme light -b 16 -o "$n.svg" "$n.drawio"
  "$DRAWIO" -x -f png -s 2 -b 16 -o "$n.png" "$n.drawio"
done
for i in 1 2; do  # the detailed diagram has two pages
  "$DRAWIO" -x -f svg --theme light -b 16 -p $i -o "architecture-detailed-$i.svg" architecture-detailed.drawio
  "$DRAWIO" -x -f png -s 2 -b 16 -p $i -o "architecture-detailed-$i.png" architecture-detailed.drawio
done
```

`--theme light` keeps the colours as drawn. Without it, draw.io makes the SVG change its colours in a dark theme.
Pages are numbered from 1. The exports here also used `-b 16`, a 16-pixel margin.

Then run `python scripts/check_publishable.py`. A PNG's compressed bytes can hold a run of digits that the scan
reads as an account id; if it flags a PNG, save the same image again at another compression level (for example
with Pillow, `compress_level=9`) and scan again. The pixels do not change.

Without the desktop app, use File → Export as → SVG (Theme: Light) and PNG (Zoom 200%) in diagrams.net, one
page at a time.
