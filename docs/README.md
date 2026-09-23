# entra documentation

- **[auth.md](auth.md)** — how sign-in works, exactly which delegated Graph
  permissions each command needs, and how to create and consent to the app
  registration. Start here; the tool does nothing useful until the
  `User.Read.All` and `AuditLog.Read.All` grants are in place.
- **[command-reference.md](command-reference.md)** — the command surface, the
  permission each one needs, and the global flags.
- **[troubleshooting.md](troubleshooting.md)** — error message to cause to fix.

Three things account for most of the confusion, and each has a section of its
own:

1. `Authorization_RequestDenied` means a missing scope, not a missing person.
2. People have two addresses — a sign-in name and an email address — and they
   differ often enough that using the wrong one looks like the account does not
   exist.
3. A person with no manager is a real state and a finding, not an error.
