# Veracode Dynamic Details

Get a summary of all the information about dynamic flaws for an application to support remediation. This includes detailed remediation information as well as request/response details.

## Setup

Clone this repository:

    git clone https://github.com/tjarrettveracode/veracode-dyn-details

Install dependencies:

    cd veracode-dyn-details
    pip install -r requirements.txt

(Optional) Save Veracode API credentials in `~/.veracode/credentials`

    [default]
    veracode_api_key_id = <YOUR_API_KEY_ID>
    veracode_api_key_secret = <YOUR_API_KEY_SECRET>

## Run

If you have saved credentials as above you can run:

    python vcdyndetails.py (arguments)

Otherwise you will need to set environment variables:

    export VERACODE_API_KEY_ID=<YOUR_API_KEY_ID>
    export VERACODE_API_KEY_SECRET=<YOUR_API_KEY_SECRET>
    python vcdyndetails.py (arguments)

Arguments supported include:

* `--appid`, `-a`: application guid for which to list a bill of materials.
* `--prompt`, `-p`: if present, will prompt for an application name. Use instead of `-a`
* `--cwe`, `-w` (opt): list of CWEs to include in the output. Use one of `--cwe`, `--category`
* `--category`, `-g` (opt): list of finding categories to include in the output. Use one of `--cwe`, `--category`

If neither `--cwe` or `--category` are used, the preview will contain all findings for the application.

## NOTES

1. This script runs on dynamic findings only.
1. All values are output to a Markdown file, `vcdyndetails.md`. There are many Markdown previewers available for Mac, Linux and Windows, or you can use an online previewer like [Dillinger](https://dillinger.io/) or a PDF conversion utility like [MarkdownToPdf](https://www.markdowntopdf.com/).
