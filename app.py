from flask import Flask, g, render_template, request, redirect, url_for, session, flash, Response
import sqlite3, os, io, csv
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import init_db as idb

# scheduling imports (add near other imports at top)
from flask_apscheduler import APScheduler
from zoneinfo import ZoneInfo
from datetime import datetime


APP_SECRET = 'change_this_secret'
# built-in admin credentials (also allowed to create accounts)
ADMIN_USER = 'admin'
ADMIN_PASS = 'Mo980616'
DB_PATH = 'maintenance.db'

MONTHS = [
    ('aug_2025', '2025-08', 'August 2025'),
    ('sep_2025', '2025-09', 'September 2025'),
    ('oct_2025', '2025-10', 'October 2025'),
    ('nov_2025', '2025-11', 'November 2025'),
    ('dec_2025', '2025-12', 'December 2025')
]

TOTAL_HOUSES = 60

# Roles driven from here and passed to admin template
ROLES = [
    ('admin', 'Admin (full access, can manage users)'),
    ('maintenance', 'Maintenance (can add maintenance records only)'),
    ('expenditure', 'Expenditure (can add expenditure records only)'),
    ('maintenance_expenditure', 'Maintenance + Expenditure (can add maintenance and expenditure)')
]

app = Flask(__name__, template_folder='templates')
app.secret_key = APP_SECRET

app.config['SCHEDULER_API_ENABLED'] = True
app.config['SCHEDULER_TIMEZONE'] = 'Asia/Kolkata'   # IMPORTANT: sends at 23:55 IST

scheduler = APScheduler()

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# ---------------------------
# Permission helpers & decorator
# ---------------------------
def is_builtin_admin():
    """Return True if session indicates builtin admin signed in."""
    return session.get('username') == ADMIN_USER and session.get('role') == 'admin'

def require_roles(*allowed_roles):
    """
    Decorator to require one of the allowed roles.
    Usage: @require_roles('admin', 'maintenance')
    Built-in admin user (username == ADMIN_USER) always allowed.
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # builtin admin always allowed
            if is_builtin_admin():
                return f(*args, **kwargs)

            role = session.get('role')
            if role in allowed_roles:
                return f(*args, **kwargs)

            flash('You do not have permission to access that page. Please log in with an account that has the necessary role.')
            return redirect(url_for('login'))
        return wrapped
    return decorator

def only_admin_required():
    """
    Inline check used in admin panel routes (return True/False).
    """
    if is_builtin_admin():
        return True
    return session.get('role') == 'admin'

def login_required(f):
    """
    Simple decorator to ensure user is logged in (either builtin admin or a DB user).
    Redirects to login page otherwise.
    """
    @wraps(f)
    def wrapped(*args, **kwargs):
        if session.get('username'):
            return f(*args, **kwargs)
        flash('You must be logged in to access that page.')
        return redirect(url_for('login'))
    return wrapped

# ---------------------------
# Utility helpers for bulk parsing
# ---------------------------
def _resolve_month_key(value):
    """
    Accepts string like '2025-08' or display key 'aug_2025' or full label.
    Returns database month key if valid, else None.
    """
    if not value:
        return None
    value = value.strip()
    # If already database key style '2025-08', accept
    for _, db_key, _ in MONTHS:
        if value == db_key:
            return db_key
    # Allow display_key like 'aug_2025'
    for display_key, db_key, _ in MONTHS:
        if value == display_key:
            return db_key
    # Allow matching label case-insensitive
    for _, db_key, label in MONTHS:
        if value.lower() == label.lower():
            return db_key
    return None

# ---------------------------
# Routes
# ---------------------------
@app.route('/')
def index():
    db = get_db()
    records = {}
    totals = {}
    expenditures_total = {}

    month_mapping = {}
    for display_key, db_key, label in MONTHS:
        month_mapping[display_key] = db_key

        cur = db.execute('SELECT * FROM records WHERE month = ? ORDER BY house_number', (db_key,))
        rows = cur.fetchall()
        records[display_key] = rows

        tot_cur = db.execute('SELECT SUM(amount) as s FROM records WHERE month = ? AND amount IS NOT NULL', (db_key,))
        payments_sum = tot_cur.fetchone()['s'] or 0

        exp_cur = db.execute('SELECT SUM(amount) as s FROM expenditures WHERE month = ?', (db_key,))
        exp_sum = exp_cur.fetchone()['s'] or 0
        expenditures_total[display_key] = int(exp_sum)

        totals[display_key] = int(payments_sum) - int(exp_sum)

    return render_template('index.html',
                           months=[(k, label) for k, _, label in MONTHS],
                           records=records,
                           totals=totals,
                           expenditures_total=expenditures_total,
                           month_mapping=month_mapping)

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        u = request.form.get('username')
        p = request.form.get('password')

        # check built-in admin first
        if u == ADMIN_USER and p == ADMIN_PASS:
            session['role'] = 'admin'
            session['username'] = ADMIN_USER
            flash('Signed in as admin')
            return redirect(url_for('index'))

        # check users table
        db = get_db()
        cur = db.execute('SELECT * FROM users WHERE username = ?', (u,))
        user = cur.fetchone()
        if user and check_password_hash(user['password_hash'], p):
            session['role'] = user['role'] or 'admin'
            session['username'] = user['username']
            flash(f"Signed in as {user['username']}")
            return redirect(url_for('index'))

        flash('Invalid credentials')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('role', None)
    session.pop('username', None)
    flash('Logged out')
    return redirect(url_for('index'))

# ----------------------
# Maintenance (payments) routes
# - /add: allowed for 'admin' and 'maintenance'
# - edit/delete: admin-only
# ----------------------
@app.route('/add', methods=['GET','POST'])
@require_roles('admin', 'maintenance', 'maintenance_expenditure')
def add():
    if request.method == 'POST':
        try:
            house = int(request.form.get('house_number'))
        except Exception:
            flash('Invalid house number')
            return redirect(url_for('add'))

        month = request.form.get('month')  # db key
        date_paid = request.form.get('date_paid') or None
        amount = request.form.get('amount')
        try:
            amount = int(amount)
        except Exception:
            amount = None
        db = get_db()
        db.execute('UPDATE records SET date_paid = ?, amount = ? WHERE house_number = ? AND month = ?', (date_paid, amount, house, month))
        db.commit()
        flash('Payment added/updated')
        return redirect(url_for('index'))

    month_options = [(db_key, label) for _, db_key, label in MONTHS]
    return render_template('add.html', total_houses=TOTAL_HOUSES, months=month_options)

@app.route('/edit/<int:rec_id>', methods=['GET','POST'])
@require_roles('admin')
def edit(rec_id):
    db = get_db()
    cur = db.execute('SELECT * FROM records WHERE id = ?', (rec_id,))
    rec = cur.fetchone()
    if not rec:
        flash('Record not found')
        return redirect(url_for('index'))
    if request.method == 'POST':
        month = request.form.get('month')
        date_paid = request.form.get('date_paid') or None
        amount = request.form.get('amount')
        try:
            amount = int(amount) if amount != '' else None
        except Exception:
            amount = None
        db.execute('UPDATE records SET month = ?, date_paid = ?, amount = ? WHERE id = ?', (month, date_paid, amount, rec_id))
        db.commit()
        flash('Record saved')
        return redirect(url_for('index'))

    month_options = [(db_key, label) for _, db_key, label in MONTHS]
    return render_template('edit.html', rec=rec, months=month_options)

@app.route('/delete/<int:rec_id>')
@require_roles('admin')
def delete(rec_id):
    db = get_db()
    db.execute('UPDATE records SET date_paid = NULL, amount = NULL WHERE id = ?', (rec_id,))
    db.commit()
    flash('Record cleared')
    return redirect(url_for('index'))

# ----------------------
# Export routes
# ----------------------
@app.route('/export/<month_key>')
def export_month(month_key):
    db_key = None
    for display_key, database_key, _ in MONTHS:
        if display_key == month_key:
            db_key = database_key
            break
    if not db_key:
        flash('Invalid month')
        return redirect(url_for('index'))

    db = get_db()
    cur = db.execute('SELECT house_number, date_paid, amount FROM records WHERE month = ? ORDER BY house_number', (db_key,))
    rows = cur.fetchall()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['House', 'Date Paid', 'Amount'])
    for r in rows:
        cw.writerow([r['house_number'], r['date_paid'] if r['date_paid'] is not None else '', r['amount'] if r['amount'] is not None else ''])
    output = si.getvalue()
    filename = f"payments_{db_key}.csv"
    return Response(output, mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename=\"{filename}\"'})

@app.route('/export_year/<year>')
def export_year(year):
    db = get_db()
    cur = db.execute('SELECT house_number, month, date_paid, amount FROM records WHERE substr(month,1,4)=? ORDER BY month, house_number', (year,))
    rows = cur.fetchall()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['House','Month','Date Paid','Amount'])
    for r in rows:
        cw.writerow([r['house_number'], r['month'], r['date_paid'] if r['date_paid'] else '', r['amount'] if r['amount'] is not None else ''])
    output = si.getvalue()
    filename = f"payments_{year}.csv"
    return Response(output, mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename=\"{filename}\"'})

# ----------------------
# Admin panel (create users)
# Only builtin admin or users with role 'admin' can access/create/delete users
# ----------------------
'''
@app.route('/admin', methods=['GET','POST'])
def admin_panel():
    if not only_admin_required():
        flash('Admin access required')
        return redirect(url_for('login'))
    db = get_db()
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password')
        role = request.form.get('role') or 'admin'
        if not username or not password:
            flash('Username and password required')
            return redirect(url_for('admin_panel'))
        password_hash = generate_password_hash(password)
        try:
            db.execute('INSERT INTO users (username, password_hash, role) VALUES (?,?,?)', (username, password_hash, role))
            db.commit()
            flash('User created')
        except sqlite3.IntegrityError:
            flash('Username already exists')
        return redirect(url_for('admin_panel'))

    users = db.execute('SELECT id, username, role FROM users ORDER BY username').fetchall()
    # pass ROLES so template can render the dropdown
    return render_template('admin.html', users=users, roles=ROLES)
'''
@app.route('/admin', methods=['GET','POST'])
def admin_panel():
    if not only_admin_required():
        flash('Admin access required')
        return redirect(url_for('login'))
    db = get_db()
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password')
        role = request.form.get('role') or 'admin'
        if not username or not password:
            flash('Username and password required')
            return redirect(url_for('admin_panel'))
        password_hash = generate_password_hash(password)
        try:
            db.execute('INSERT INTO users (username, password_hash, role) VALUES (?,?,?)', (username, password_hash, role))
            db.commit()
            flash('User created')
        except sqlite3.IntegrityError:
            flash('Username already exists')
        return redirect(url_for('admin_panel'))

    users = db.execute('SELECT id, username, role FROM users ORDER BY username').fetchall()
    # ✅ Load backup emails from extra.db and pass into template
    try:
        edb = get_extra_db()
        emails = edb.execute(
            'SELECT id, email, added_by, created_at FROM backup_emails ORDER BY email'
        ).fetchall()
    except Exception:
        emails = []

    # pass ROLES so template can render the dropdown and pass emails
    return render_template('admin.html', users=users, roles=ROLES, emails=emails)

@app.route('/admin/delete_user/<int:user_id>')
def delete_user(user_id):
    if not only_admin_required():
        flash('Admin access required')
        return redirect(url_for('login'))
    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    flash('User deleted')
    return redirect(url_for('admin_panel'))

# ----------------------
# Bulk upload endpoints (admin-only)
#
# Maintenance CSV format (expected header or order):
# House, Month, Date Paid, Amount
# 1, 2025-08, 02-08-2025, 1200
#
# Expenditure CSV format (expected header or order):
# Month, Date, Amount, Type, Reason
# 2025-08, 03-08-2025, 3500, Repair, 'Pump repaired'
# ----------------------
@app.route('/admin/bulk_upload_maintenance', methods=['GET', 'POST'])
def bulk_upload_maintenance():
    if not only_admin_required():
        flash('Admin access required to upload files')
        return redirect(url_for('login'))

    if request.method == 'POST':
        uploaded = request.files.get('file')
        if not uploaded:
            flash('No file uploaded')
            return redirect(url_for('admin_panel'))

        try:
            stream = io.StringIO(uploaded.stream.read().decode('utf-8-sig'))
        except Exception:
            flash('Could not read uploaded file (ensure it is a text CSV in UTF-8).')
            return redirect(url_for('admin_panel'))

        reader = csv.reader(stream)
        rows = list(reader)
        if not rows:
            flash('CSV is empty')
            return redirect(url_for('admin_panel'))

        # If header line present, detect it (check first row for non-numeric house)
        header = rows[0]
        start_idx = 0
        if len(header) >= 1:
            first_cell = header[0].strip().lower()
            if first_cell in ('house', 'house number', 'house_number'):
                start_idx = 1

        db = get_db()
        success_count = 0
        error_rows = []
        for idx, row in enumerate(rows[start_idx:], start=start_idx+1):
            if not row or all([c.strip()=='' for c in row]):
                # skip blank lines
                continue
            # Expected columns: House, Month, Date Paid, Amount
            # Accept if fewer columns (try to parse best we can)
            try:
                house_raw = row[0].strip()
                month_raw = row[1].strip() if len(row) > 1 else ''
                date_paid_raw = row[2].strip() if len(row) > 2 else ''
                amount_raw = row[3].strip() if len(row) > 3 else ''
            except Exception:
                error_rows.append((idx, 'Malformed row'))
                continue

            # validate house
            try:
                house = int(house_raw)
                if house < 1 or house > TOTAL_HOUSES:
                    raise ValueError('House number out of range')
            except Exception as e:
                error_rows.append((idx, f'Invalid house: {house_raw} ({e})'))
                continue

            # validate month -> convert to db_key like '2025-08'
            month_key = _resolve_month_key(month_raw)
            if not month_key:
                error_rows.append((idx, f'Invalid month: {month_raw}'))
                continue

            date_paid = date_paid_raw if date_paid_raw != '' else None
            if amount_raw == '':
                amount = None
            else:
                try:
                    amount = int(amount_raw)
                except Exception:
                    error_rows.append((idx, f'Invalid amount: {amount_raw}'))
                    continue

            # Update records table if row exists for house/month, else report error
            cur = db.execute('SELECT id FROM records WHERE house_number = ? AND month = ?', (house, month_key))
            rec = cur.fetchone()
            if not rec:
                # Optionally, we could insert a new record — but current DB layout likely pre-seeded.
                error_rows.append((idx, f'No record for house {house} and month {month_key}'))
                continue

            try:
                db.execute('UPDATE records SET date_paid = ?, amount = ? WHERE house_number = ? AND month = ?', (date_paid, amount, house, month_key))
                success_count += 1
            except Exception as e:
                error_rows.append((idx, f'DB error: {e}'))
                continue

        db.commit()
        flash(f'Bulk upload complete: {success_count} rows processed, {len(error_rows)} errors')
        if error_rows:
            # Show up to first 10 errors in flash (more can be logged)
            for e in error_rows[:10]:
                flash(f'Row {e[0]}: {e[1]}')
        return redirect(url_for('admin_panel'))

    # GET - ideally you will POST from admin panel. Provide a minimal instruction page if someone navigates here.
    return render_template('admin_bulk_upload_maintenance.html', months=[(db_key, label) for _, db_key, label in MONTHS])

@app.route('/admin/bulk_upload_expenditure', methods=['GET', 'POST'])
def bulk_upload_expenditure():
    if not only_admin_required():
        flash('Admin access required to upload files')
        return redirect(url_for('login'))

    if request.method == 'POST':
        uploaded = request.files.get('file')
        if not uploaded:
            flash('No file uploaded')
            return redirect(url_for('admin_panel'))

        try:
            stream = io.StringIO(uploaded.stream.read().decode('utf-8-sig'))
        except Exception:
            flash('Could not read uploaded file (ensure it is a text CSV in UTF-8).')
            return redirect(url_for('admin_panel'))

        reader = csv.reader(stream)
        rows = list(reader)
        if not rows:
            flash('CSV is empty')
            return redirect(url_for('admin_panel'))

        # If header line present, detect it (check first row for something non-date or 'month')
        header = rows[0]
        start_idx = 0
        hdr0 = header[0].strip().lower() if header else ''
        if hdr0 in ('month', 'date', 'amount', 'type', 'reason'):
            start_idx = 1

        db = get_db()
        success_count = 0
        error_rows = []
        for idx, row in enumerate(rows[start_idx:], start=start_idx+1):
            if not row or all([c.strip()=='' for c in row]):
                continue
            # Expected columns: Month, Date, Amount, Type, Reason
            try:
                month_raw = row[0].strip() if len(row) > 0 else ''
                date_raw = row[1].strip() if len(row) > 1 else ''
                amount_raw = row[2].strip() if len(row) > 2 else ''
                type_raw = row[3].strip() if len(row) > 3 else ''
                reason_raw = row[4].strip() if len(row) > 4 else ''
            except Exception:
                error_rows.append((idx, 'Malformed row'))
                continue

            month_key = _resolve_month_key(month_raw)
            if not month_key:
                error_rows.append((idx, f'Invalid month: {month_raw}'))
                continue

            date = date_raw if date_raw != '' else None
            try:
                amount = int(amount_raw)
            except Exception:
                error_rows.append((idx, f'Invalid amount: {amount_raw}'))
                continue

            exp_type = type_raw or None
            reason = reason_raw or ''

            created_by = session.get('username') or ADMIN_USER
            try:
                db.execute('INSERT INTO expenditures (month, date, amount, type, reason, created_by) VALUES (?,?,?,?,?,?)',
                           (month_key, date, amount, exp_type, reason, created_by))
                success_count += 1
            except Exception as e:
                error_rows.append((idx, f'DB error: {e}'))
                continue

        db.commit()
        flash(f'Expenditure bulk upload: {success_count} rows added, {len(error_rows)} errors')
        if error_rows:
            for e in error_rows[:10]:
                flash(f'Row {e[0]}: {e[1]}')
        return redirect(url_for('expenditure'))

    # GET - minimal instruction page
    return render_template('admin_bulk_upload_expenditure.html', months=[(db_key, label) for _, db_key, label in MONTHS])

# ----------------------
# Password management routes (ADDED)
# ----------------------
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """
    Allows the currently logged-in DB user to change their own password.
    Built-in admin (username==ADMIN_USER) cannot change ADMIN_PASS here (it's code constant).
    """
    username = session.get('username')
    # prevent builtin admin from using this to change the code-based ADMIN_PASS
    if username == ADMIN_USER:
        flash('Built-in admin password is defined in code and cannot be changed via this interface. To change it, update ADMIN_PASS in your app configuration.')
        return redirect(url_for('index'))

    db = get_db()
    cur = db.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cur.fetchone()
    if not user:
        flash('User record not found')
        return redirect(url_for('index'))

    if request.method == 'POST':
        current = request.form.get('current_password') or ''
        newp = request.form.get('new_password') or ''
        confirm = request.form.get('confirm_password') or ''

        if not current or not newp or not confirm:
            flash('All fields are required')
            return redirect(url_for('change_password'))

        # verify current password
        if not check_password_hash(user['password_hash'], current):
            flash('Current password is incorrect')
            return redirect(url_for('change_password'))

        if newp != confirm:
            flash('New password and confirmation do not match')
            return redirect(url_for('change_password'))

        if len(newp) < 6:
            flash('New password should be at least 6 characters long')
            return redirect(url_for('change_password'))

        new_hash = generate_password_hash(newp)
        db.execute('UPDATE users SET password_hash = ? WHERE username = ?', (new_hash, username))
        db.commit()
        flash('Password changed successfully')
        return redirect(url_for('index'))

    return render_template('change_password.html', username=username)

@app.route('/admin/reset_password/<int:user_id>', methods=['GET', 'POST'])
def admin_reset_password(user_id):
    """
    Admin-only route to reset another user's password without needing their current password.
    Accessible to builtin admin and users with role 'admin'.
    """
    if not only_admin_required():
        flash('Admin access required')
        return redirect(url_for('login'))

    db = get_db()
    cur = db.execute('SELECT id, username, role FROM users WHERE id = ?', (user_id,))
    user = cur.fetchone()
    if not user:
        flash('User not found')
        return redirect(url_for('admin_panel'))

    if request.method == 'POST':
        newp = request.form.get('new_password') or ''
        confirm = request.form.get('confirm_password') or ''
        if not newp or not confirm:
            flash('Both password fields are required')
            return redirect(url_for('admin_reset_password', user_id=user_id))
        if newp != confirm:
            flash('Passwords do not match')
            return redirect(url_for('admin_reset_password', user_id=user_id))
        if len(newp) < 6:
            flash('New password should be at least 6 characters long')
            return redirect(url_for('admin_reset_password', user_id=user_id))

        new_hash = generate_password_hash(newp)
        db.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_hash, user_id))
        db.commit()
        flash(f"Password for user '{user['username']}' has been reset")
        return redirect(url_for('admin_panel'))

    # GET
    return render_template('admin_reset_password.html', user=user)

# ----------------------
# Expenditure routes
# - Viewable by anyone
# - Only admin or expenditure role (or builtin admin) can POST (add)
# - Deleting is admin-only
# ----------------------
# ---------- Expenditure routes (updated) ----------
@app.route('/expenditure', methods=['GET','POST'])
def expenditure():
    db = get_db()

    # POST (create) -> restrict to admin/expenditure
    if request.method == 'POST':
        if not (is_builtin_admin() or session.get('role') in ('admin', 'expenditure', 'maintenance_expenditure')):
            flash('You do not have permission to add expenditures. Please log in with an account that has the necessary role.')
            return redirect(url_for('login'))

        month = request.form.get('month')  # database key like '2025-08'
        date = request.form.get('date') or None
        amount = request.form.get('amount') or '0'
        exp_type = request.form.get('type')
        reason = request.form.get('reason') or ''
        try:
            amount = int(amount)
        except Exception:
            flash('Invalid amount')
            return redirect(url_for('expenditure'))

        created_by = session.get('username') or 'unknown'
        db.execute('INSERT INTO expenditures (month, date, amount, type, reason, created_by) VALUES (?,?,?,?,?,?)',
                   (month, date, amount, exp_type, reason, created_by))
        db.commit()
        flash('Expenditure recorded')
        return redirect(url_for('expenditure'))

    # GET -> support optional month filter via query param ?month=YYYY-MM
    selected_month = request.args.get('month')  # e.g. '2025-08' or None for all
    if selected_month:
        cur = db.execute('SELECT * FROM expenditures WHERE month = ? ORDER BY date DESC, id DESC', (selected_month,))
    else:
        cur = db.execute('SELECT * FROM expenditures ORDER BY month DESC, date DESC, id DESC')
    exp_rows = cur.fetchall()

    # month options for filter / form
    month_options = [(db_key, label) for _, db_key, label in MONTHS]
    return render_template('expenditure.html',
                           expenditures=exp_rows,
                           months=month_options,
                           selected_month=selected_month)

@app.route('/expenditure/export')
def export_expenditures():
    """
    Export expenditures to CSV. Optional query param: ?month=YYYY-MM
    If month is provided, only that month's expenditures are exported; otherwise all.
    """
    db = get_db()
    month = request.args.get('month')
    if month:
        cur = db.execute('SELECT month, date, amount, type, reason, created_by FROM expenditures WHERE month = ? ORDER BY date DESC, id DESC', (month,))
        filename = f"expenditures_{month}.csv"
    else:
        cur = db.execute('SELECT month, date, amount, type, reason, created_by FROM expenditures ORDER BY month DESC, date DESC, id DESC')
        filename = "expenditures_all.csv"

    rows = cur.fetchall()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Month', 'Date', 'Amount', 'Type', 'Reason', 'Created By'])
    for r in rows:
        cw.writerow([
            r['month'],
            r['date'] if r['date'] else '',
            r['amount'] if r['amount'] is not None else '',
            r['type'] or '',
            r['reason'] or '',
            r['created_by'] or ''
        ])
    output = si.getvalue()
    return Response(output, mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename=\"{filename}\"'})

@app.route('/expenditure/delete/<int:exp_id>')
@require_roles('admin')
def delete_expenditure(exp_id):
    db = get_db()
    db.execute('DELETE FROM expenditures WHERE id = ?', (exp_id,))
    db.commit()
    flash('Expenditure deleted')
    return redirect(url_for('expenditure'))

@app.route("/photo")
def photo_page():
    # Example: static/picture/sample.jpg
    image_url = url_for('static', filename='picture/sample.jpg')
    return render_template(
        "show_photo.html",
        image_url=image_url,
        caption="Modern City Layout",
        alt="Modern City Layout"
    )

# ------------------- START: APPENDED extra.db + backup email/send-backup code -------------------
# New imports used by appended code
import smtplib, traceback
from email.message import EmailMessage
from datetime import datetime

# Separate DB path for backup emails (so maintenance.db is untouched)
EXTRA_DB_PATH = 'extra.db'

def get_extra_db():
    """Open extra.db and ensure backup_emails table exists (created on first access)."""
    db = getattr(g, '_extra_database', None)
    if db is None:
        # create file/connection
        db = g._extra_database = sqlite3.connect(EXTRA_DB_PATH)
        db.row_factory = sqlite3.Row
        # ensure table exists
        db.execute("""
        CREATE TABLE IF NOT EXISTS backup_emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            added_by TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
        """)
        db.commit()
    return db

# ensure extra DB connection closed too
@app.teardown_appcontext
def close_extra_connection(exception):
    edb = getattr(g, '_extra_database', None)
    if edb is not None:
        edb.close()

# SMTP settings (update these to your provider)
SMTP_HOST = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USERNAME = 'modernmohitraj@gmail.com'
SMTP_PASSWORD = 'twdyupohdfrvyurc'
EMAIL_FROM = 'modernmohitraj@gmail.com'
def send_email_with_attachments(smtp_host, smtp_port, username, password, sender, recipients, subject, body_text, attachments):
    """
    attachments: list of tuples (filename, content_str_or_bytes, mime_type)
    Returns (success_bool, message)
    """
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = ', '.join(recipients)
    msg.set_content(body_text)

    for fname, content, mime_type in attachments:
        if isinstance(content, str):
            content_bytes = content.encode('utf-8')
        else:
            content_bytes = content
        maintype, subtype = ('application', 'octet-stream')
        if mime_type:
            try:
                maintype, subtype = mime_type.split('/', 1)
            except Exception:
                maintype, subtype = ('application', 'octet-stream')
        msg.add_attachment(content_bytes, maintype=maintype, subtype=subtype, filename=fname)

    try:
        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=30)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
            server.ehlo()
            try:
                server.starttls()
                server.ehlo()
            except Exception:
                pass
        if username and password:
            server.login(username, password)
        server.send_message(msg)
        server.quit()
        return True, "Sent"
    except Exception as e:
        return False, f"Error sending email: {e}\n{traceback.format_exc()}"

# CSV generators (reuse same queries as your export routes)
def _generate_payments_csv_string_for_month(db, month_db_key):
    cur = db.execute('SELECT house_number, date_paid, amount FROM records WHERE month = ? ORDER BY house_number', (month_db_key,))
    rows = cur.fetchall()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['House', 'Date Paid', 'Amount'])
    for r in rows:
        cw.writerow([r['house_number'], r['date_paid'] if r['date_paid'] is not None else '', r['amount'] if r['amount'] is not None else ''])
    return f"payments_{month_db_key}.csv", si.getvalue()

def _generate_payments_csv_string_for_year(db, year):
    cur = db.execute('SELECT house_number, month, date_paid, amount FROM records WHERE substr(month,1,4)=? ORDER BY month, house_number', (year,))
    rows = cur.fetchall()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['House','Month','Date Paid','Amount'])
    for r in rows:
        cw.writerow([r['house_number'], r['month'], r['date_paid'] if r['date_paid'] else '', r['amount'] if r['amount'] is not None else ''])
    return f"payments_{year}.csv", si.getvalue()

def _generate_expenditures_csv_string(db, month=None):
    if month:
        cur = db.execute('SELECT month, date, amount, type, reason, created_by FROM expenditures WHERE month = ? ORDER BY date DESC, id DESC', (month,))
        filename = f"expenditures_{month}.csv"
    else:
        cur = db.execute('SELECT month, date, amount, type, reason, created_by FROM expenditures ORDER BY month DESC, date DESC, id DESC')
        filename = "expenditures_all.csv"
    rows = cur.fetchall()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Month', 'Date', 'Amount', 'Type', 'Reason', 'Created By'])
    for r in rows:
        cw.writerow([
            r['month'],
            r['date'] if r['date'] else '',
            r['amount'] if r['amount'] is not None else '',
            r['type'] or '',
            r['reason'] or '',
            r['created_by'] or ''
        ])
    return filename, si.getvalue()
'''
# New route to manage backup emails (stored in extra.db)
@app.route('/admin/backup_emails', methods=['GET', 'POST'])
def admin_backup_emails():
    if not only_admin_required():
        flash('Admin access required')
        return redirect(url_for('login'))
    edb = get_extra_db()
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        if not email:
            flash('Email required')
            return redirect(url_for('admin_backup_emails'))
        try:
            edb.execute('INSERT INTO backup_emails (email, added_by) VALUES (?, ?)', (email, session.get('username') or 'admin'))
            edb.commit()
            flash('Email added')
        except sqlite3.IntegrityError:
            flash('Email already exists')
        return redirect(url_for('admin_backup_emails'))

    emails = edb.execute('SELECT id, email, added_by, created_at FROM backup_emails ORDER BY email').fetchall()
    # If you have a dedicated template for listing emails:
    # return render_template('admin_backup_emails.html', emails=emails)
    # To keep things minimal and safe (no assumptions about templates), reuse admin.html if it can accept 'emails'.
    # But original admin_panel did not pass emails, so render a small dedicated page:
    return render_template('admin_backup_emails.html', emails=emails)
'''
@app.route('/admin/backup_emails', methods=['GET', 'POST'])
def admin_backup_emails():
    if not only_admin_required():
        flash('Admin access required')
        return redirect(url_for('login'))

    edb = get_extra_db()

    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        if not email:
            flash('Email required')
            # Redirect back to admin page and open backup-emails section
            return redirect(url_for('admin_panel') + '#backup-emails')
        try:
            edb.execute(
                'INSERT INTO backup_emails (email, added_by) VALUES (?, ?)',
                (email, session.get('username') or 'admin')
            )
            edb.commit()
            flash('Email added')
        except sqlite3.IntegrityError:
            flash('Email already exists')
        # After adding, return to admin page and open the backup-emails section
        return redirect(url_for('admin_panel') + '#backup-emails')

    # For GET requests, just redirect to the admin page's backup section.
    # The admin page should be responsible for loading and passing `emails` to the template.
    return redirect(url_for('admin_panel') + '#backup-emails')


'''
@app.route('/admin/backup_emails/delete/<int:email_id>')
def delete_backup_email(email_id):
    if not only_admin_required():
        flash('Admin access required')
        return redirect(url_for('login'))
    edb = get_extra_db()
    edb.execute('DELETE FROM backup_emails WHERE id = ?', (email_id,))
    edb.commit()
    flash('Email removed')
    return redirect(url_for('admin_backup_emails'))
'''
@app.route('/admin/backup_emails/delete/<int:email_id>')
def delete_backup_email(email_id):
    if not only_admin_required():
        flash('Admin access required')
        return redirect(url_for('login'))
    edb = get_extra_db()
    edb.execute('DELETE FROM backup_emails WHERE id = ?', (email_id,))
    edb.commit()
    flash('Email removed')
    # return to admin page backup section
    return redirect(url_for('admin_panel') + '#backup-emails')

# Route to generate CSVs and email to configured backup emails
@app.route('/send_backup', methods=['GET', 'POST'])
def send_backup():
    if not only_admin_required():
        flash('Admin access required')
        return redirect(url_for('login'))

    db = get_db()
    edb = get_extra_db()

    if request.method == 'POST':
        month_payments = (request.form.get('month_for_payments') or '').strip()
        year_payments = (request.form.get('year_for_payments') or '').strip()
        month_exps = (request.form.get('month_for_expenditures') or '').strip()

        rows = edb.execute('SELECT email FROM backup_emails').fetchall()
        recipients = [r['email'] for r in rows]
        if not recipients:
            flash('No backup emails configured. Add addresses at Admin → Backup Emails')
            return redirect(url_for('admin_backup_emails'))

        attachments = []
        if month_payments:
            fname, content = _generate_payments_csv_string_for_month(db, month_payments)
            attachments.append((fname, content, 'text/csv'))
        elif year_payments:
            fname, content = _generate_payments_csv_string_for_year(db, year_payments)
            attachments.append((fname, content, 'text/csv'))
        else:
            curr_year = datetime.utcnow().strftime('%Y')
            fname, content = _generate_payments_csv_string_for_year(db, curr_year)
            attachments.append((fname, content, 'text/csv'))

        if month_exps:
            fname, content = _generate_expenditures_csv_string(db, month_exps)
            attachments.append((fname, content, 'text/csv'))
        else:
            fname, content = _generate_expenditures_csv_string(db, None)
            attachments.append((fname, content, 'text/csv'))

        subject = f"Backup - Payments & Expenditures ({datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')})"
        body = ("Attached are the exported CSV files for payments and expenditures.\n\n"
                "If you need a different month/year, please use the form and re-send.\n\n"
                "This is an automated message from the maintenance app.")

        success, message = send_email_with_attachments(
            SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, EMAIL_FROM,
            recipients, subject, body, attachments
        )
        if success:
            flash(f'Backup emailed to {len(recipients)} address(es).')
        else:
            flash(f'Failed to send backup: {message}')
        return redirect(url_for('admin_backup_emails'))

    # GET -> show simple form (template should be created as send_backup.html)
    month_options = [(db_key, label) for _, db_key, label in MONTHS]
    return render_template('send_backup.html', months=month_options)



# The scheduled job. It uses the same CSV generators + send_email_with_attachments helpers
# It runs within an app context so get_db() and get_extra_db() work.
@scheduler.task('cron', id='daily_backup_job', hour=23, minute=55)
def daily_backup_job():
    try:
        with app.app_context():
            # Build DB connections
            db = get_db()
            edb = get_extra_db()

            # Collect recipients from extra.db
            rows = edb.execute('SELECT email FROM backup_emails').fetchall()
            recipients = [r['email'] for r in rows]
            if not recipients:
                print("[daily_backup_job] No backup emails configured; aborting send.")
                return

            # Determine month key in Asia/Kolkata timezone (send current month's CSVs)
            now_kolkata = datetime.now(ZoneInfo("Asia/Kolkata"))
            month_key = now_kolkata.strftime('%Y-%m')
            year_key = now_kolkata.strftime('%Y')

            # Attachments: payments for current month and expenditures for current month
            attachments = []
            try:
                fname_p, content_p = _generate_payments_csv_string_for_month(db, month_key)
                attachments.append((fname_p, content_p, 'text/csv'))
            except Exception as e:
                print(f"[daily_backup_job] Error generating payments CSV for {month_key}: {e}")

            try:
                fname_e, content_e = _generate_expenditures_csv_string(db, month_key)
                attachments.append((fname_e, content_e, 'text/csv'))
            except Exception as e:
                print(f"[daily_backup_job] Error generating expenditures CSV for {month_key}: {e}")

            if not attachments:
                print("[daily_backup_job] No attachments prepared; aborting send.")
                return

            subject = f"Automated Backup: payments & expenditures ({now_kolkata.strftime('%Y-%m-%d %H:%M %Z')})"
            body = (
                "Attached are the automated backup CSVs for payments and expenditures.\n\n"
                "If you would like a different month/year, use the app's Send Backup form.\n\n"
                "This is an automated message from the maintenance app."
            )

            success, message = send_email_with_attachments(
                SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, EMAIL_FROM,
                recipients, subject, body, attachments
            )

            if success:
                print(f"[daily_backup_job] Backup emailed to {len(recipients)} recipient(s).")
            else:
                print(f"[daily_backup_job] Failed to send backup: {message}")

    except Exception as ex:
        print(f"[daily_backup_job] Unexpected exception: {ex}\n{traceback.format_exc()}")

# ------------------- END: Scheduler block -------------------

# ------------------- END: APPENDED code -------------------

# ----------------------
# Run
# ----------------------
if __name__ == '__main__':
    if not os.path.exists(DB_PATH):
        print("Database not found. Run 'python init_db.py' to create it.")
        idb.main()
    scheduler.init_app(app)
    # in dev, avoid double-start from the reloader:
    scheduler.start()
    app.run(host="0.0.0.0", debug=True)