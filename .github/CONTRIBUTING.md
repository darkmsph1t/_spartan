# Contributing to _spartan

First, thank you for considering contributing to this project! There are so many directions I want to go with it, and there's no way I can do it all by myself.

## Getting Help & Resources
- Here: Please use Github to post new issues, bugs and feature requests. This is also where the primary user documentation resides, so start here first.
  - The project roadmap will eventually land on the repo wiki page.
- Slack: [_spartan-users-group](https://spartan-ug.slack.com/). Fair warning though, I do have a day job, so I might not respond immediately, but I'll make every attempt to respond to you within 48 hours. Slack is where I'll post annoucements about upcoming releases and major changes. You can also use this medium to ask questions about _spartan. Currently, it is by invitation only...essentially, if I see that you have forked/cloned the repo, I'll send you an invitation. Be forewarned: the code of conduct here also applies there and I reserve the right to moderate content as well as boot people who are being abusive or otherwise contrarian.
- Twitter: @darkmsph1t. I almost never post things and I only follow infosec & coding topics/people, but if there's something _spartan-related I'll post links to it in Twitter. I would say use this contact medium as a last resort. Same RoE with respect to the code of conduct, RE: abuse, hate-speech or any other toxic BS. 

## Testing
Still getting my legs under me on this front. I'll update this once I have a real game plan here, but for now, please add your test-cases & results as generic issues with the title beginning with: **Test Case => **

## Submitting changes

Please send a [GitHub Pull Request to _spartan](https://github.com/darkmsph1t/_spartan/pull/new/master) with a clear list of what you've done (read more about [pull requests](http://help.github.com/pull-requests/)). When you send a pull request, I will love you forever if it includes a couple things: 
  1. Clear commit message which tells me what this is doing along with a PR body which describes the impact & changes
  1. Some indication of how to test it prior to approval. 
  1. If it's related to an issue or will address multiple issues, please link to those in the body of the PR comments

Please follow the coding conventions (below) and make sure all of your commits are atomic (one feature per commit).

## Coding conventions

Start reading our code and you'll get the hang of it. We optimize for readability:

  * Include comments, but bug reports don't belong there. 
  * Currently the code base is in Javascript, so please include `module.exports.[some method name] = [some method name]` statements at the end of your methods.
  * If needed, use absolute paths instead of relative paths
  * We avoid logic in views, putting HTML generators into helpers
  * This is open source software. Consider the people who will read your code, and make it look nice for them. It's sort of like driving a car: Perhaps you love doing donuts when you're alone, but with passengers the goal is to make the ride as smooth as possible.

Thanks,
The dArk m$ph1t
