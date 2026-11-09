---
name: provide-context
description: >
  Analyse the repository for missing context and interview the user to provide it.
---

Review the code provided by the user. If the user does not provide any code, walk the codebase and do a general review. Your aim is to identify missing context that isn't provided by the code itself and ask the user questions to fill in that information.

- Only ask questions that fill gaps in context which are necessary to understand the codebase, typically where there isn't a clear aim or purpose for a file, function, or module.
- Don't manufacture issues. If the code is clear and self-explanatory, say so and stop.

When asking questions, be specific and provide examples of what you are trying to determine. Every
question should have the option for the user to answer that they don't know, or that they are
unsure.

Once you have identified and answered the missing context, create a plan for where to incorporate it
into the codebase, such as in comments, CLAUDE.md files in each directory, or in the repositories
documentation.
