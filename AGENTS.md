This project is a DNS wide ad blocker written in Go

# Structure
`/internal` - The innterworkings of the codebase 
- `/blacklist` - Where blocking is being done. Allowlist should also exist here
- `/parser` - Where the DNS message is parsed 
`/config` - Where the `config.yaml` file is parsed
`/cmd` - Where the code is instantiated and such
`/tests` - Where integration tests (using Python) are stored. 

# Guidelines 
- Creating tests for everything is not a necessity. Always prefer integration and E2E testing over unit tests
