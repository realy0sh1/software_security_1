# Player
- Tim Niklas Gruel 1080 2021 2831
- username: realy0sh1

# Writeup: "tinyalloc"
- story: He's making a list And checking it twice Gonna find out Who's naughty and nice
- This task has a different setup in the Dockerfile — this is a TCP server (not HTTP though) that can accept multiple connections without having to be respawned! 

# startup
```
docker compose up
```

# Overview
- sparns new thread for each connection
- we can wriet 64 bytes into command
- we can call "get presents" and spawn a new thread at the same time
    - new thread resets counter to 0 and we pass naughty check

# flag:
```
softsec{seXZzZe1DL2HD3SHlXSzOc8fL4EAXaeNcgoJUJP5Y0i47kVYvWY11CBgsn_2s5M_}
```