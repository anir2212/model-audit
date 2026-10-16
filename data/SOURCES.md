# Data sources and provenance

Both archives were downloaded on 12 October 2026 from the official [UCI Default of Credit Card Clients](https://archive.ics.uci.edu/dataset/350/default) and [UCI Statlog German Credit](https://archive.ics.uci.edu/dataset/144/statlog+german+credit+data) pages. Both pages state **CC BY 4.0**; credit the named creators and the UCI repository when reusing them. The files are excluded from Git. `python -m data.fetch` downloads missing archives and verifies the SHA-256 digests below before modeling.

| Archive | Creator and UCI citation | SHA-256 |
|---|---|---|
| `uci_taiwan_350.zip` | I-Cheng Yeh, *Default of Credit Card Clients*, UCI, DOI `10.24432/C55S3H` | `56c885f84457f6680f8438f02bfcdac9579323d8a94465ee5f26e32baa727602` |
| `uci_german_144.zip` | Hans Hofmann, *Statlog (German Credit Data)*, UCI, DOI `10.24432/C5NC77` | `e12d9d5def6845c0622634a1cd2ab87fa470668c4298f1ec52a4e403376a435b` |

Taiwan has 30,000 rows, 23 predictors and a next-month default flag. The archive has no row-level application timestamp. This project sorts its ID values and uses rows 1–18,000 for training, 18,001–24,000 for validation/confirmation and 24,001–30,000 for test. **ID order is only a proxy cohort split, not a true out-of-time split.** The survival experiment uses the six repayment-status fields in April-to-September order to define a *first two-month delinquency* proxy; it does not observe actual time-to-default. Its baseline covariates come from nonmonthly attributes.

German Credit has 1,000 rows and 20 predictors; a stratified random 750/250 split is used. Attribute 9 combines personal status and sex; the derived sex slice is imperfect and should not be treated as a clean protected-attribute measurement. The original source includes a cost matrix which is documented but not yet optimized in this project. Neither dataset represents current Singapore applicants or an authorized lending policy.
