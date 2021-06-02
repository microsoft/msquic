# Contributing to MsQuic

We'd love your help with MsQuic! Here are our contribution guidelines.

- [Code of Conduct](#code-of-conduct)
- [Bugs](#bugs)
- [New Features](#new-features)
- [Contributor License Agreement](#contributor-license-agreement)
- [Contributing Code](#contributing-code)
  - [Process](#process)
  - [Tests](#tests)

## Code of Conduct

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Microsoft Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with additional questions or comments.

## Bugs

One of the easiest ways to contribute is to participate in discussion on GitHub issues.

If you find a non-security related bug, you can help us by [submitting a GitHub Issue](https://github.com/microsoft/msquic/issues/new/choose). The best bug reports provide a detailed description of the issue and step-by-step instructions for reliably reproducing the issue. Even better, you can submit a Pull Request with a fix.

If you find a security issue, please **do not open a GitHub Issue**, and instead follow [these instructions](SECURITY.md).

## New Features

You can request a new feature by [submitting a GitHub Issue](https://github.com/microsoft/msquic/issues/new/choose).

If you would like to implement a new feature, please first [submit a GitHub Issue](https://github.com/microsoft/msquic/issues/new/choose) and communicate your proposal so that the community can review and provide feedback. Getting early feedback will help ensure your implementation work is accepted by the community. This will also allow us to better coordinate our efforts and minimize duplicated effort.

## Contributor License Agreement

You will need to complete a Contributor License Agreement (CLA) for any code submissions. Briefly, this agreement testifies that you are granting us permission to use the submitted change according to the terms of the project's license, and that the work being submitted is under appropriate copyright. You only need to do this once. For more information see https://cla.opensource.microsoft.com/.

## Contributing Code

We accept fixes and features! Here are some resources to help you get started on how to contribute code or new content.

* Look at the [documentation](../docs/) to get started on building the source code on your own.
* ["Help wanted" issues](https://github.com/microsoft/msquic/labels/help%20wanted) - these issues are up for grabs. Comment on an issue if you want to create a fix.
* ["Good first issue" issues](https://github.com/microsoft/msquic/labels/good%20first%20issue) - we think these are a good for newcomers.

### Process

For all but the absolute simplest changes, first [submit a GitHub Issue](https://github.com/microsoft/msquic/issues/new/choose) so that the community can review and provide feedback. Getting early feedback will help ensure your work is accepted by the community. This will also allow us to better coordinate our efforts and minimize duplicated effort.

If you would like to contribute, first identify the scale of what you would like to contribute. If it is small (grammar/spelling or a bug fix) feel free to start working on a fix. If you are submitting a feature or substantial code contribution, please discuss it with the team and ensure it follows the product roadmap. You might also read these two blogs posts on contributing code: [Open Source Contribution Etiquette](http://tirania.org/blog/archive/2010/Dec-31.html) by Miguel de Icaza and [Don't "Push" Your Pull Requests](https://www.igvita.com/2011/12/19/dont-push-your-pull-requests/) by Ilya Grigorik. All code submissions will be rigorously reviewed and tested by the team, and only those that meet the bar for both quality and design/roadmap appropriateness will be merged into the source.

### Tests

We have tests to prevent regressions and validate functionality. For all new Pull Requests the following rules apply:

- Existing tests should continue to pass.
- Tests need to be provided for every bug/feature that is completed.
- Tests only need to be present for issues that need to be verified by QA (for example, not tasks)
- If there is a scenario that is far too hard to test there does not need to be a test for it.
  - "Too hard" is determined by the team as a whole, and should be considered extremely rare.

## Governance

This project is actively maintained and managed by Microsoft, with a primary goal of supporting the Windows OS. Therefore, Microsoft reserves the right to the final say in all decisions to ensure the success of this goal.
