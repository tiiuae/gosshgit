# gosshgit

Go implementation of git ssh server


```
gitsrv := gosshgit.New("git-repositories")
err := gitsrv.Initialize()
if err != nil {
	panic("could not initialize git server")
}

// read the public key from e.g. ~/.ssh/id_ed25519.pub to grant local git access to the server
gitsrv.Allow(publicKey)

err = g.InitBareRepo("test.git")
if err != nil {
	panic("could not create repo")
}

err = g.ListenAndServe(":2222")
if err != nil {
	panic("could not serve")
}
```

Clone the test.git repository
```
git clone ssh://git@localhost:2222/test.git
```
