#!/usr/bin/env python3
from stem.control import Controller
c = Controller.from_port(port=9051)
c.authenticate()
print(c.get_info("version"))
c.close()
