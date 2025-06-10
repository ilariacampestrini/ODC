from libdebug import debugger

d = debugger("./provola")

print(1)

# Start debugging from the entry point
d.run()
d.cont()

print(2)

d.wait()

# Kill the process
d.kill()
