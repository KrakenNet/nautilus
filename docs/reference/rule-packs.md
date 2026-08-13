# Rule Packs

A rule pack is an installable bundle of Fathom rules registered under the
`fathom.packs` entry-point group. Packs are resolved by **name**, not by
filesystem path, so a third-party pack installed from PyPI loads exactly the way
a shipped one does.

Nautilus ships two packs.

## Loading a rule pack

In `nautilus.yaml`:

```yaml
rules:
  packs:
    - data-routing-nist
    - data-routing-hipaa
```

Or directly, when constructing a router:

```python
from nautilus.core.fathom_router import FathomRouter
from nautilus.rules import BUILT_IN_RULES_DIR

router = FathomRouter(
    built_in_rules_dir=BUILT_IN_RULES_DIR,
    user_rules_dirs=[],
    rule_packs=["data-routing-nist"],
)
```

Packs load after the built-in rules and after `user_rules_dirs`. Their rules
join the built-in `nautilus-routing` module: they match against the same working
memory as the built-in routing rules and interleave with them by salience, using
the standard bands — denial 170–190, scope constraint 130–150, escalation
110–120.

## Pack layout

`RulePackLoader` scans the package the entry point resolves to and loads, in
order, whichever of these directories exist:

```
templates/    # load_templates
modules/      # load_modules
functions/    # load_functions
rules/        # load_rules
```

Nothing else is loaded. In particular a `hierarchies/` directory is **not**
read — a pack that ships one is shipping a file the engine never sees.

`pack.yaml` is descriptive metadata for humans and tooling; the loader does not
read it.

## data-routing-nist

NIST SP 800-53 access control. Implements AC-6 (least privilege, emits a
`scope_constraint` binding confidential-and-above sources to the agent's stated
purpose) and AC-16 (security attributes, denies a source carrying no
classification label).

Other controls the pack previously advertised are not implemented, because their
conditions cannot be expressed over the facts the broker asserts. See the pack
README for the control-by-control reasons.

## data-routing-hipaa

HIPAA Privacy Rule constraints. Implements minimum necessary (45 CFR 164.502(b))
and the treatment/payment/operations purpose limitation (45 CFR 164.506).

## Writing a pack

Declare the entry point in your `pyproject.toml`:

```toml
[project.entry-points."fathom.packs"]
my-pack = "my_package.my_pack"
```

`my_package.my_pack` must be an importable package (it needs an `__init__.py`)
whose directory holds the `rules/` subdirectory above, and your build backend
must be configured to include the YAML in the wheel — for setuptools:

```toml
[tool.setuptools.package-data]
"my_package.my_pack" = ["**/*.yaml"]
```

A pack that points at a non-importable module, or whose YAML is left out of the
wheel, fails at load time rather than at install time.

## Compliance disclaimer

Both shipped packs are **reference implementations only** — they are not
certified for production compliance. Organizations must validate rules against
their specific regulatory requirements and engage qualified compliance
personnel.
