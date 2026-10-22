import os
import sqlite3

from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signup.db")

DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
# Half-hour slots from 2:00 to 4:00 pm, stored as 24-hour start times.
TIMES = ["14:00", "14:30", "15:00", "15:30"]

app = Flask(__name__)
# Set SECRET_KEY in the environment for anything beyond local development.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or os.urandom(32)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DATABASE) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
            """
        )
        # One row per booked slot; the UNIQUE constraint keeps two users
        # from booking the same slot even if their requests race.
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS bookings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                day INTEGER NOT NULL,
                start_time TEXT NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users (id),
                UNIQUE (day, start_time)
            )
            """
        )


def slot_label(start_time):
    hour, minute = map(int, start_time.split(":"))
    end_hour, end_minute = (hour, 30) if minute == 0 else (hour + 1, 0)
    return f"{hour - 12}:{minute:02d} – {end_hour - 12}:{end_minute:02d} pm"


def parse_slot(form):
    """Return (day, start_time) from a submitted form, or None if invalid."""
    try:
        day = int(form.get("day", ""))
    except ValueError:
        return None
    start_time = form.get("start_time", "")
    if not 0 <= day < len(DAYS) or start_time not in TIMES:
        return None
    return day, start_time


@app.before_request
def load_user():
    user_id = session.get("user_id")
    g.user = None
    g.is_admin = False
    if user_id is not None:
        db = get_db()
        g.user = db.execute(
            "SELECT id, username FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if g.user is not None:
            # The first user who registered is the administrator.
            first_id = db.execute("SELECT MIN(id) FROM users").fetchone()[0]
            g.is_admin = g.user["id"] == first_id


@app.route("/")
def index():
    if g.user is None:
        return render_template("index.html")

    rows = get_db().execute(
        """
        SELECT b.day, b.start_time, b.user_id, u.username
        FROM bookings b JOIN users u ON u.id = b.user_id
        """
    ).fetchall()
    booked = {(row["day"], row["start_time"]): row for row in rows}

    # Build the sheet as rows of times, one cell per weekday. Only the
    # administrator gets other people's names; everyone else just sees
    # whether a slot is free, theirs, or taken.
    sheet = []
    for start_time in TIMES:
        cells = []
        for day in range(len(DAYS)):
            row = booked.get((day, start_time))
            if row is None:
                status, name = "free", None
            elif row["user_id"] == g.user["id"]:
                status, name = "mine", None
            else:
                status = "taken"
                name = row["username"] if g.is_admin else None
            cells.append(
                {"day": day, "start_time": start_time, "status": status, "name": name}
            )
        sheet.append({"label": slot_label(start_time), "cells": cells})
    return render_template("index.html", days=DAYS, sheet=sheet)


@app.route("/book", methods=["POST"])
def book():
    if g.user is None:
        return redirect(url_for("login"))
    slot = parse_slot(request.form)
    if slot is None:
        flash("That slot does not exist.", "error")
        return redirect(url_for("index"))
    day, start_time = slot
    try:
        db = get_db()
        db.execute(
            "INSERT INTO bookings (day, start_time, user_id) VALUES (?, ?, ?)",
            (day, start_time, g.user["id"]),
        )
        db.commit()
    except sqlite3.IntegrityError:
        flash("Sorry, that slot was just taken.", "error")
    else:
        flash(f"Booked {DAYS[day]}, {slot_label(start_time)}.", "success")
    return redirect(url_for("index"))


@app.route("/cancel", methods=["POST"])
def cancel():
    if g.user is None:
        return redirect(url_for("login"))
    slot = parse_slot(request.form)
    if slot is None:
        flash("That slot does not exist.", "error")
        return redirect(url_for("index"))
    day, start_time = slot
    db = get_db()
    # Matching on user_id means a user can only ever cancel their own booking.
    cursor = db.execute(
        "DELETE FROM bookings WHERE day = ? AND start_time = ? AND user_id = ?",
        (day, start_time, g.user["id"]),
    )
    db.commit()
    if cursor.rowcount:
        flash(f"Cancelled {DAYS[day]}, {slot_label(start_time)}.", "success")
    else:
        flash("You have no booking in that slot.", "error")
    return redirect(url_for("index"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        error = None
        if not username:
            error = "Username is required."
        elif not password:
            error = "Password is required."

        if error is None:
            # generate_password_hash uses scrypt with a random per-user salt;
            # the salt and parameters are stored inside the hash string.
            try:
                db = get_db()
                db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
            except sqlite3.IntegrityError:
                error = f"User {username} is already registered."
            else:
                flash("Registration successful. Please log in.", "success")
                return redirect(url_for("login"))
        flash(error, "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Incorrect username or password.", "error")
        else:
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("index"))


init_db()

if __name__ == "__main__":
    app.run(debug=True)
