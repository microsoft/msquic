阅读本文的其他语言版本：[English](https://github.com/microsoft/msquic/blob/main/.github/CONTRIBUTING.md)
# 为MsQuic做贡献

我们希望您对MsQuic的帮助！这是我们的贡献准则。

- [行为守则](#code-of-conduct)
- [虫子](#bugs)
- [新的功能](#new-features)
- [贡献者许可协议](#contributor-license-agreement)
- [贡献代码](#contributing-code)
  - [处理](#process)
  - [测验](#tests)

> **重要**-我们仍在为核心代码提供重要的回归测试。在将它们加入计算机之前，将不接受对[core]（../ src / core）或[platform]（../ src / platform）中的内核模式文件的任何外部贡献。这只是“临时限制”，我们正在努力在2020年底之前完成。
＃＃ 行为守则

该项目采用了[Microsoft开放源代码行为准则]（https://opensource.microsoft.com/codeofconduct/）。有关更多信息，请参见[Microsoft行为准则常见问题解答]（https://opensource.microsoft.com/codeofconduct/faq/）或与[opencode@microsoft.com]（mailto：opencode@microsoft.com）联系，或有其他问题，或评论。

## 错误

贡献的最简单方法之一就是参与有关GitHub问题的讨论。

如果发现与安全无关的错误，可以通过[提交GitHub问题]（https://github.com/microsoft/msquic/issues/new/choose）来帮助我们。最佳错误报告提供了有关问题的详细说明，并提供了可靠地重现问题的分步说明。更好的是，您可以提交包含修复程序的请求请求。

如果发现安全问题，请**不要打开GitHub问题**，而应遵循[这些说明]（SECURITY.md）。

## 新的功能

您可以通过[提交GitHub问题]（https://github.com/microsoft/msquic/issues/new/choose）来请求一项新功能。

如果您想实施一项新功能，请首先[提交GitHub问题]（https://github.com/microsoft/msquic/issues/new/choose）并传达您的建议，以便社区可以审查并提供反馈。尽早获得反馈将有助于确保您的实施工作被社区接受。这也将使我们能够更好地协调我们的努力，并减少重复的努力。

## 贡献者许可协议

您需要完成任何代码提交的贡献者许可协议（CLA）。简而言之，该协议证明您已根据项目许可的条款授予我们使用提交的更改的权限，并且所提交的作品具有适当的版权。您只需要执行一次。有关更多信息，请参见https://cla.opensource.microsoft.com/。

## 贡献代码

我们接受修复和功能！这里有一些资源可以帮助您开始如何贡献代码或新内容。

*查看[documentation]（../ docs /），开始自行构建源代码。
* [“帮助通缉”问题]（https://github.com/microsoft/msquic/labels/help%20wanted）-这些问题亟待解决。如果要创建修复程序，请对问题发表评论。
* [“好第一期”问题]（https://github.com/microsoft/msquic/labels/good%20first%20issue）-我们认为这些对新人来说是一件好事。

### 流程

对于除绝对最简单的更改以外的所有更改，请首先[提交GitHub问题]（https://github.com/microsoft/msquic/issues/new/choose），以便社区可以查看并提供反馈。尽早获得反馈将有助于确保您的工作被社区所接受。这也将使我们能够更好地协调我们的努力，并减少重复的努力。

如果您想贡献，首先确定您想贡献的规模。如果很小（语法/拼写或错误修复），请随时开始进行修复。如果您要提交功能或大量代码贡献，请与团队讨论并确保其遵循产品路线图。您可能还会阅读这两篇有关贡献代码的博​​客文章：Miguel de Icaza撰写的[Open Source Contribution Etiquette]（http://tirania.org/blog/archive/2010/Dec-31.html）和[Do n't“ Push “您的拉取请求]（Ilya Grigorik的）（https://www.igvita.com/2011/12/19/dont-push-your-pull-requests/）。该团队将严格审查和测试所有提交的代码，只有那些同时满足质量和设计/路线图适用性要求的代码才会被合并到源代码中。

### 测试

我们进行了测试以防止回归并验证功能。对于所有新的“拉取请求”，以下规则适用：

-现有测试应继续通过。
-需要为完成的每个错误/功能提供测试。
-仅针对需要质量检查确认的问题进行测试（例如，不执行任务）
-如果存在很难测试的场景，则无需对其进行测试。
  -“太难了”是由团队整体决定的，应该被认为是极为罕见的。
