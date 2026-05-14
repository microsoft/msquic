# MsQuic Task management 

## Work item states 

| State                    | Mark                                | Other Details                                          | Query Example                                         |
|--------------------------|-------------------------------------|--------------------------------------------------------|-------------------------------------------------------|
| **Triage Needed**        | Not in any other state              |                                                        | [`is:issue state:open no:project -label:"help wanted"`](https://github.com/microsoft/msquic/issues?q=is%3Aissue%20state%3Aopen%20no%3Aproject%20-label%3A%22help%20wanted%22) |
| **Non-prioritized Work** | Not in DPT project, `help wanted`   | Type, Area                                             | [`is:issue state:open label:"help wanted"`](https://github.com/microsoft/msquic/issues?q=is%3Aissue%20state%3Aopen%20label%3A%22help%20wanted%22) |
| **Backlog**              | In DPT project, no status           | Type, Area, Priority, T-Shirt size                     | [Backlog - DPT Iteration Tracker](https://github.com/orgs/microsoft/projects/1617/views/6)                       |
| **Current Work**         | In DPT project, Planned/In Progress | Type, Area, Priority, T-Shirt size, Iteration, Assignee| [Breakdown - DPT Iteration Tracker](https://github.com/orgs/microsoft/projects/1617/views/1) |
| **Closed**               | Closed                              | Reason label if not completed (e.g., Cut: NotRepro)    |                                                       |


### Triage Needed 

Every newly created work items must be triaged to evaluate whether it should be worked on and with which priority.
A work item is in the “Triage needed” state by default until it is assigned to another state. 

Work items are triaged in a regular team triage meeting:
- the work item is moved to one of the category below
- common metadata is added: Type (Bug / Task / Feature), Area label (`Area: *`), Priority (P0 to P3), T-Shirt size (XS to XL)...

### Help wanted

Some work items, while interesting, are not aligned with our priorities.
These work items are labeled with `help wanted` and are not added in the "DPT Iteration Tracker" project nor prioritized.
If there is interest about addressing these work items, a contribution would be welcome.

During triage, these work item should be labeled with `help wanted`, and receive a type and area labels (`Area: *`).

### Backlog 

The work items the team plans to work on in the future, prioritized and roughly sized. 

During triage, these work items should be added to the “DPT Iteration tracker” project without a status, and get a type, a priority (P0 to P3), a T-Shirt size (XS to XL), and an area label (`Area: *`). If relevant, a partner label (`Partner: *`) should also be added. 

### Current work 

Work items that have been picked up by the team to be worked on during a specific iteration. 

During triage/planning, they should get the “Planned” status, an iteration and be assigned to a dev, in addition to what is set to backlog items.
When working on the item, the assignee should change the state to “In Progress”, then “Done” to reflect progress.

### Closed 

Work items that don’t require additional work are closed. They can be completed or cut.
If the work item was not completed, it should be labeled with `Cut: *` (NotRepro / WontFix/ Duplicate...). 
