# Notices

## This project

behavry-verify

Copyright 2026 Behavry

Source code in this repository is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE). You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.

## Bundled fonts

`web/fonts/` contains font files redistributed under the **SIL Open Font License 1.1**, not Apache-2.0. They are vendored rather than loaded from a CDN because this site's Content-Security-Policy is `default-src 'self'`, and because a page whose purpose is to let you verify evidence without trusting anyone should not pull assets from a third party.

| Font | Copyright | License |
|---|---|---|
| Inter | Copyright 2016 The Inter Project Authors, https://github.com/rsms/inter | [OFL 1.1](web/fonts/LICENSE-Inter.txt) |
| JetBrains Mono | Copyright 2020 The JetBrains Mono Project Authors, https://github.com/JetBrains/JetBrainsMono | [OFL 1.1](web/fonts/LICENSE-JetBrainsMono.txt) |

If you fork this repository and keep the fonts, you must keep those license files with them.

## Trademarks

"Behavry", the Behavry name, and the logo files in `web/brand/` are trademarks of Behavry. The Apache-2.0 license covers the source code and **does not** grant permission to use the Behavry name or marks.

You may fork this code and run your own verifier. If you do, replace the contents of `web/brand/` and the product name in `web/index.html` with your own, so that no one mistakes your deployment for one operated by Behavry. This matters more than usual here: the whole point of this service is telling someone whether a piece of evidence is authentic, and a verifier that appears to be Behavry's but is not would undermine exactly the trust it exists to establish.
