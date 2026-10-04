# Final integration checks

The application source includes the optional pinned instruction scanner, one-pass AST indexing, bounded compound npm-hook handling, correct UTF8 source positions, and the chamber target working directory.

The final code passed **172 scoped checks** and Ruff. Static decision signatures and success states match all **45** recorded inputs. Normal configured S1 activation on one inert skill instruction produced five advisory findings with no omissions or parse errors, using the existing trusted scanner and isolated container. This check made no inference, search, chamber or audited-target calls.

The sealed evidence checkpoint remains byte-identical. Its source binding predates the final UTF8 correction; [verification.json](verification.json) and [source-only-verification.json](source-only-verification.json) bind the final 39 source files and the separate correction. The original paired result remains **36 complete audits and four partials**. These final checks do not replace the original model or chamber measurement.

A fresh Docker image build was denied before its build context was read because the sandbox could not write Docker Buildx activity state. No retry or workaround was made. Fresh final-image build and deployment smoke remain unverified.

[Installed activation](installed-activation.json), [selected evidence recount](selected-recount.json), [test output](tests.log), and [Ruff output](ruff.log) retain the observed checks. All 3,241 historical benchmark files and three owner files matched the intake preservation hashes.
