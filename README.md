dropper
=======

Tool for automatic ROP chain generation

dropper aim to automatically generate a ROP chain capable of spwaning
a shell once injected in the stack of an executable.

It is in a very early stage of development and without documentation
:(

It uses the BARF framework [0] under the hood (but actually it works only
with the version of my fork[1]).

Dependencies
============

- BARF (actually this fork[1])
- Pyelftools


Example
=======
    from dropper import dropper
    dr = dropper.dropper('/bin/ls')
    dr.analyze_all()
    dr.add_shared_object('/lib/x86_64-linux-gnu/libc.so.6')
    dr.set_function_for_address_resolving('strrchr')
    pl = dr.build_spawn_shell_payload()

TODO
====

* It's very slow
* Analyze other categories of gadgets
* Better chain generation
* Use planning as rop chain generation strategy!

Feel free con contact me for info

rizlik@inventati.org

[0] https://github.com/programa-stic/barf-project.git
[1] https://github.com/rizlik/barf-project.git
