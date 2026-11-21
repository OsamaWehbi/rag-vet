# Engineering handbook

Welcome to the team. This page covers how we work day to day.

## Code review

Every change goes through a pull request and needs one approval. Keep pull requests small:
under 400 lines is a good target.

## Writing accessible HTML

Hide decorative elements from screen readers, and never hide real content with CSS. For example,
this pattern hides content from everyone and should be avoided:

```html
<div style="display:none">Important notice</div>
```

## Useful links

- The REST API for repositories lives at `https://api.github.com/repos/{owner}/{repo}`.
- Our [style guide](https://example.com/style-guide "Company style guide") explains naming rules.
- ![Team photo](https://example.com/images/team.png)

<!-- TODO: add the on-call rota -->

Questions go to the #engineering channel.
