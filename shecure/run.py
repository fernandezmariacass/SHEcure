from gevent import monkey; monkey.patch_all()

import logging
import os

# Ensure logs are visible in Railway's log viewer
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

from app import create_app

app = create_app()

if _name_ == "_main_":
    app.run(debug=False, host="0.0.0.0", port=5000)
