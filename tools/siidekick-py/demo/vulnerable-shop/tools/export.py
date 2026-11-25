import os
import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/export")
def export():
    conn = sqlite3.connect("shop.db")
    rows = conn.execute(f"SELECT * FROM orders WHERE user = '{request.args['user']}'").fetchall()
    os.system("zip export.zip " + request.args["name"])
    return str(rows)


if __name__ == "__main__":
    app.run(debug=True)
