# Release Process

## Changelog Discipline

- Add user-visible changes to `CHANGELOG.md` as they land.
- Keep entries under `Unreleased` until a version is cut.
- Use the stable categories `Added`, `Changed`, `Fixed`, and `Docs`.
- Move `Unreleased` entries into a versioned section during release prep.

## Where Information Belongs

- `README.md`: what the tool is, how to build and run it, sample output, and current limitations.
- `CHANGELOG.md`: concise version-by-version history of user-visible changes.
- GitHub release notes: a short release announcement built from the changelog, with highlights and upgrade context.

## Practical Rule

If a change affects external readers or users, it should usually touch either `README.md`, `CHANGELOG.md`, or both.
