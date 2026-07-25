# GRAFT

GRAFT is a rule-evolution framework for improving black-box Web Application
Firewalls (WAFs). It discovers target-relative blind spots, generates
structured detection rules with an OpenAI-compatible language model, and uses
a validation set to select effective rules.

## Features

- WAF blind-spot discovery
- Red-team payload mutation
- Multi-view HTTP request analysis
- LLM-based structured rule generation
- Validation-governed rule selection
- Rule contribution graph and lifecycle reports

## Install

```bash
python -m pip install -e .
```

## Configuration

Set the following environment variables:

```bash
GRAFT_LLM_API_KEY=your_api_key
GRAFT_LLM_BASE_URL=https://api.openai.com/v1
GRAFT_LLM_MODEL=your_model
```

See [.env.example](.env.example) for all available options.

## Quick Start

```bash
graft --help
```

See [examples/mini](examples/mini) for an offline example and
[docs/data-format.md](docs/data-format.md) for the input format.

## License

Released under the [GNU Affero General Public License v3.0](LICENSE).
