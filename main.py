
import os
import re
import json
import csv
import asyncio
import sqlite3
import hashlib
from io import StringIO
from datetime import datetime
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes,
    CallbackQueryHandler,
    ConversationHandler
)
import logging

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Conversation states
(EMAIL, PASSWORD, MAIN_MENU, APP_SELECTION, ACTIVATION_PROOF, 
 ADMIN_MODE, ADD_APP_MODE, EDIT_APP_MODE, TOGGLE_APP_MODE, 
 REPORT_MODE, DELETE_REPORT_MODE, DELETE_USER_MODE, ADD_USER,
 IMPORT_DATA_MODE) = range(14)

# Database configuration
DB_DIR = "Database"
os.makedirs(DB_DIR, exist_ok=True)
DB_FILE = os.path.join(DB_DIR, "earner_community.db")

# Initialize database
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Create tables if they don't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT NOT NULL,
        chat_id TEXT,
        created_at TEXT NOT NULL
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS activations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        mobile TEXT NOT NULL,
        app TEXT NOT NULL,
        status TEXT NOT NULL,
        reason TEXT,
        timestamp TEXT NOT NULL,
        submission_date TEXT NOT NULL,
        message_id TEXT,
        UNIQUE(email, mobile, app) ON CONFLICT IGNORE
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS apps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        report_time TEXT NOT NULL,
        report_updated TEXT NOT NULL,
        status INTEGER NOT NULL DEFAULT 0
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS guides (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL
    )
    ''')
    
    # Insert default apps if none exist
    cursor.execute('SELECT COUNT(*) FROM apps')
    if cursor.fetchone()[0] == 0:
        default_apps = [
            ("paytmmoney", "every 2 days", "16 July", 0),
            ("angelone", "daily", "15 July", 0),
            ("lemonn", "weekly", "14 July", 0),
            ("mstock", "every 3 days", "13 July", 0),
            ("upstox", "monthly", "12 July", 0)
        ]
        cursor.executemany('INSERT INTO apps (name, report_time, report_updated, status) VALUES (?, ?, ?, ?)', default_apps)
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

# Apps that require screenshots
SCREENSHOT_APPS = ['mstock', 'angelone']

# Status messages
STATUS_MESSAGES = {
    "approved": "✅ Approved",
    "rejected": "❌ Rejected",
    "pending": "⏳ Pending",
    "enabled": "🟢 Enabled",
    "disabled": "🔴 Disabled"
}

# Rejection reasons
REJECTION_REASONS = {
    "77": "Incorrect Proof - Video/screenshot is incorrect, send correct recording showing process",
    "78": "Improper Activation - Activation not done properly, send correct video",
    "79": "Fraud Detected - Fraud detected, account not showing",
    "80": "Wrong Device - Activation not done on user's device",
    "81": "Late Submission - Activation completed after deadline",
    "nt": "Non Trade Approved"
}

# --- Database Helper Functions ---
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

async def execute_db_query(query, params=(), fetch_one=False, fetch_all=False, commit=False):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(query, params)
        if commit:
            conn.commit()
        if fetch_one:
            return cursor.fetchone()
        if fetch_all:
            return cursor.fetchall()
        return cursor.lastrowid
    except Exception as e:
        logger.error(f"Database error: {e}")
        raise
    finally:
        conn.close()

async def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# --- User Management ---
async def read_emails():
    query = "SELECT email, password, name, chat_id FROM users"
    users = await execute_db_query(query, fetch_all=True)
    return {user['email']: dict(user) for user in users}

async def add_user(email, password, name, chat_id=None):
    if not all([email, password, name]):
        return False, "Missing required fields"
        
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return False, "Invalid email format"

    hashed_pw = await hash_password(password)
    query = "INSERT INTO users (email, password, name, chat_id, created_at) VALUES (?, ?, ?, ?, ?)"
    
    try:
        await execute_db_query(query, (email.lower(), hashed_pw, name, chat_id, datetime.now().isoformat()), commit=True)
        return True, "User added successfully"
    except sqlite3.IntegrityError:
        return False, "User already exists"
    except Exception as e:
        logger.error(f"Error adding user: {e}")
        return False, "Failed to add user"

async def delete_user(email, password):
    hashed_pw = await hash_password(password)
    query = "DELETE FROM users WHERE email = ? AND password = ?"
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(query, (email.lower(), hashed_pw))
        conn.commit()
        result = cursor.rowcount > 0
        conn.close()
        return result
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        return False

# --- App Management ---
async def read_apps(include_disabled=False):
    query = "SELECT * FROM apps" if include_disabled else "SELECT * FROM apps WHERE status = 0"
    return await execute_db_query(query, fetch_all=True)

async def add_app(app_name):
    if not app_name or not re.match(r'^[a-z0-9]+$', app_name):
        return False, "Invalid app name (only lowercase letters and numbers allowed)"

    query = "INSERT INTO apps (name, report_time, report_updated, status) VALUES (?, ?, ?, ?)"
    
    try:
        await execute_db_query(query, (app_name.lower(), "daily", datetime.now().strftime('%d %B'), 0), commit=True)
        return True, "App added successfully"
    except sqlite3.IntegrityError:
        return False, "App already exists"
    except Exception as e:
        logger.error(f"Error adding app: {e}")
        return False, "Failed to add app"

async def delete_app(app_name):
    query = "DELETE FROM apps WHERE name = ?"
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(query, (app_name.lower(),))
        conn.commit()
        result = cursor.rowcount > 0
        conn.close()
        return (True, "App deleted successfully") if result else (False, "App not found")
    except Exception as e:
        logger.error(f"Error deleting app: {e}")
        return False, "Failed to delete app"

async def update_app_time(app_name, report_time, report_updated):
    query = "UPDATE apps SET report_time = ?, report_updated = ? WHERE name = ?"
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(query, (report_time, report_updated, app_name.lower()))
        conn.commit()
        result = cursor.rowcount > 0
        conn.close()
        return (True, "App report time updated") if result else (False, "App not found")
    except Exception as e:
        logger.error(f"Error updating app time: {e}")
        return False, "Failed to update app time"

async def toggle_app_status(app_name):
    query = "UPDATE apps SET status = 1 - status WHERE name = ?"
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(query, (app_name.lower(),))
        conn.commit()
        if cursor.rowcount > 0:
            cursor.execute("SELECT status FROM apps WHERE name = ?", (app_name.lower(),))
            status = cursor.fetchone()[0]
            status_text = 'disabled' if status else 'enabled'
            conn.close()
            return True, f"App {app_name} {status_text}"
        conn.close()
        return False, "App not found"
    except Exception as e:
        logger.error(f"Error toggling app status: {e}")
        return False, "Failed to toggle app status"

# --- Activation Management ---
async def read_activations(email=None, app=None, mobile=None, limit=None, offset=0):
    conditions = []
    params = []
    
    if email:
        conditions.append("email = ?")
        params.append(email)
    if app:
        conditions.append("app = ?")
        params.append(app)
    if mobile:
        conditions.append("mobile = ?")
        params.append(mobile.replace(" ", ""))
    
    where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
    limit_clause = f"LIMIT {limit} OFFSET {offset}" if limit else ""
    
    query = f"SELECT * FROM activations {where_clause} ORDER BY timestamp DESC {limit_clause}"
    return await execute_db_query(query, params, fetch_all=True)

async def is_duplicate(app, mobile, email=None):
    conditions = ["app = ?", "mobile = ?", "status IN ('pending', 'approved')"]
    params = [app, mobile.replace(" ", "")]
    
    if email:
        conditions.append("email = ?")
        params.append(email)
    
    query = f"SELECT 1 FROM activations WHERE {' AND '.join(conditions)} LIMIT 1"
    result = await execute_db_query(query, params, fetch_one=True)
    return bool(result)

async def write_activation(email, app, mobile, status="pending", reason="pending"):
    if not all([email, app, mobile]):
        return False
        
    query = """
    INSERT INTO activations 
    (email, mobile, app, status, reason, timestamp, submission_date) 
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """
    
    try:
        await execute_db_query(query, (
            email,
            mobile.replace(" ", ""),
            app,
            status,
            reason,
            datetime.now().isoformat(),
            datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ), commit=True)
        return True
    except Exception as e:
        logger.error(f"Error writing activation: {e}")
        return False

async def update_activation(email, app, mobile, status, reason="0"):
    query = """
    UPDATE activations 
    SET status = ?, reason = ?, timestamp = ?
    WHERE app = ? AND mobile = ?
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(query, (
            status,
            reason,
            datetime.now().isoformat(),
            app,
            mobile.replace(" ", "")
        ))
        conn.commit()
        result = cursor.rowcount > 0
        conn.close()
        return result
    except Exception as e:
        logger.error(f"Error updating activation: {e}")
        return False

async def delete_activation(app, mobile):
    query = "DELETE FROM activations WHERE app = ? AND mobile = ?"
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(query, (app, mobile.replace(" ", "")))
        conn.commit()
        result = cursor.rowcount > 0
        conn.close()
        return result
    except Exception as e:
        logger.error(f"Error deleting activation: {e}")
        return False

# --- Guide & Rules Management ---
async def read_guide():
    query = "SELECT * FROM guides LIMIT 1"
    guide = await execute_db_query(query, fetch_one=True)
    if guide:
        return dict(guide)
    return {"title": "Guide", "content": "Guide content not available"}

async def read_rules():
    query = "SELECT * FROM rules LIMIT 1"
    rules = await execute_db_query(query, fetch_one=True)
    if rules:
        return dict(rules)
    return {"title": "Rules", "content": "Rules content not available"}

# --- Data Import/Export ---
async def generate_csv_report():
    try:
        # Activation report
        activation_output = StringIO()
        activation_writer = csv.writer(activation_output)
        activation_writer.writerow(["Email", "Mobile", "App", "Status", "Reason", "Submission Date"])
        
        activations = await read_activations(limit=10000)
        for act in activations:
            activation_writer.writerow([
                act['email'],
                act['mobile'],
                act['app'],
                act['status'],
                REJECTION_REASONS.get(act['reason'], act['reason']),
                act['submission_date']
            ])
        
        # User report
        user_output = StringIO()
        user_writer = csv.writer(user_output)
        user_writer.writerow(["Email", "Name", "Created At"])
        
        query = "SELECT email, name, created_at FROM users LIMIT 10000"
        users = await execute_db_query(query, fetch_all=True)
        for user in users:
            user_writer.writerow([
                user['email'],
                user['name'],
                user['created_at']
            ])
        
        return activation_output.getvalue(), user_output.getvalue()
    except Exception as e:
        logger.error(f"Error generating CSV: {e}")
        return None, None

async def import_json_data(update: Update, context: ContextTypes.DEFAULT_TYPE, file_type: str, json_data: list):
    try:
        if file_type == 'users':
            imported = 0
            duplicates = 0
            for user in json_data:
                try:
                    # Skip if password is already hashed (assuming 64 chars for SHA256)
                    password = user['password'] if len(user['password']) == 64 else await hash_password(user['password'])
                    query = """
                    INSERT INTO users (email, password, name, chat_id, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """
                    await execute_db_query(query, (
                        user['email'].lower(),
                        password,
                        user['name'],
                        user.get('chat_id'),
                        user.get('created_at', datetime.now().isoformat())
                    ), commit=True)
                    imported += 1
                except sqlite3.IntegrityError:
                    duplicates += 1
                    continue
            return f"✅ Users imported: {imported}\n🚫 Duplicates skipped: {duplicates}"
        
        elif file_type == 'activations':
            imported = 0
            duplicates = 0
            for act in json_data:
                try:
                    query = """
                    INSERT INTO activations 
                    (email, mobile, app, status, reason, timestamp, submission_date, message_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """
                    await execute_db_query(query, (
                        act['email'],
                        act['mobile'].replace(" ", ""),
                        act['app'],
                        act.get('status', 'pending'),
                        act.get('reason', '0'),
                        act.get('timestamp', datetime.now().isoformat()),
                        act.get('submission_date', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                        act.get('message_id')
                    ), commit=True)
                    imported += 1
                except sqlite3.IntegrityError:
                    duplicates += 1
                    continue
            return f"✅ Activations imported: {imported}\n🚫 Duplicates skipped: {duplicates}"
        
        return "❌ Unknown file type"
    except Exception as e:
        logger.error(f"Error importing {file_type} data: {e}")
        return f"❌ Error importing data: {str(e)}"

# --- Bot Handlers ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if str(update.effective_user.id) == os.getenv('ADMIN_CHAT_ID'):
        await update.message.reply_text(
            "👑 *Admin Mode*\n\n"
            "Use /adminmode to enter admin panel\n"
            "Use /cancel to exit any operation",
            parse_mode='Markdown'
        )
        return ConversationHandler.END

    email = context.user_data.get('email')
    if email:
        users = await read_emails()
        if email in users:
            return await main_menu(update, context)

    context.user_data['chat_id'] = update.effective_chat.id
    await update.message.reply_text(
        "🌟 *Welcome to Earner Community Activation Bot!* 🌟\n\n"
        "Please enter your registered *email address*:",
        parse_mode='Markdown'
    )
    return EMAIL

async def email_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    email = update.message.text.strip().lower()
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        await update.message.reply_text("❌ Invalid email format. Please enter a valid email address:")
        return EMAIL
    context.user_data['email'] = email
    await update.message.reply_text("🔒 Please enter your *password*:", parse_mode='Markdown')
    return PASSWORD

async def password_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    password = update.message.text.strip()
    if len(password) < 6:
        await update.message.reply_text("❌ Password must be at least 6 characters. Please try again:")
        return PASSWORD

    email = context.user_data['email']
    users = await read_emails()

    if email in users:
        hashed_input = await hash_password(password)
        if users[email]['password'] == hashed_input:
            # Update chat_id if not set or changed
            query = "UPDATE users SET chat_id = ? WHERE email = ?"
            await execute_db_query(query, (update.effective_chat.id, email), commit=True)

            context.user_data['name'] = users[email]['name']
            await update.message.reply_text("✅ *Login successful!* 🎉", parse_mode='Markdown')
            return await main_menu(update, context)

    await update.message.reply_text(
        "❌ *Invalid email or password.*\n\n"
        "Please enter your *email address* again:",
        parse_mode='Markdown'
    )
    return EMAIL

async def main_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    try:
        if not context.user_data.get('email'):
            await update.message.reply_text("❌ Please /start to login first")
            return ConversationHandler.END

        if update.callback_query:
            await update.callback_query.answer()
            message_editor = update.callback_query.edit_message_text
        else:
            message_editor = update.message.reply_text

        name = context.user_data.get('name', 'User')
        email = context.user_data.get('email', '')

        keyboard = [
            [InlineKeyboardButton("📊 My Activation Status", callback_data='status')],
            [InlineKeyboardButton("📤 Send Activation Proof", callback_data='proof')],
            [InlineKeyboardButton("📖 How To Work Guide", callback_data='guide')],
            [InlineKeyboardButton("📜 Activation Rules", callback_data='rules')],
            [InlineKeyboardButton("⏰ Report Timing", callback_data='report_timing')],
        ]

        await message_editor(
            f"👋 *Hello {name}!* ({email})\n\n"
            "🔹 *Activation Dashboard* - Please select an option:",
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return MAIN_MENU
    except Exception as e:
        logger.error(f"Error in main_menu: {e}")
        await handle_error(update, context)
        return ConversationHandler.END

async def menu_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not context.user_data.get('email'):
        await update.message.reply_text("❌ Please /start to login first")
        return ConversationHandler.END
    return await main_menu(update, context)

async def activation_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Show activation status with pagination"""
    try:
        query = update.callback_query
        await query.answer()

        offset = context.user_data.get('status_offset', 0)
        email = context.user_data['email']
        activations = await read_activations(email=email, limit=5, offset=offset)

        if activations:
            text = "📊 *Your Activation Status:*\n\n"
            for act in activations:
                status = act['status'].lower()
                reason = REJECTION_REASONS.get(act['reason'], act['reason'])
                
                status_emoji = "✅" if status == "approved" else "❌" if status == "rejected" else "⏳"
                status_display = status.capitalize()
                
                text += (
                    f"{status_emoji} *{act['app'].upper()}*\n"
                    f"📱 *Mobile:* `{act['mobile']}`\n"
                    f"🔄 *Status:* {status_display}\n"
                    f"📝 *Reason:* {reason}\n"
                    f"📅 *Date:* {act['submission_date'].split()[0]}\n\n"
                )
        else:
            text = "ℹ️ No activations found. Submit your first activation proof!"

        keyboard = []
        
        # Pagination controls
        if offset > 0:
            keyboard.append([InlineKeyboardButton("⬅️ Previous", callback_data='prev_page')])
        
        if len(activations) == 5:  # If we got a full page
            keyboard.append([InlineKeyboardButton("➡️ Next", callback_data='next_page')])
        
        keyboard.append([InlineKeyboardButton("🔙 Back", callback_data='back')])

        await query.edit_message_text(
            text,
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return MAIN_MENU
    except Exception as e:
        logger.error(f"Error in activation_status: {e}")
        await query.edit_message_text(
            "❌ Error loading your status. Please try again.",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data='back')]
            ])
        )
        return MAIN_MENU

async def handle_pagination(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()

    current_offset = context.user_data.get('status_offset', 0)
    
    if query.data == 'next_page':
        context.user_data['status_offset'] = current_offset + 5
    elif query.data == 'prev_page':
        context.user_data['status_offset'] = max(0, current_offset - 5)

    return await activation_status(update, context)

async def send_activation_proof(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    try:
        query = update.callback_query
        await query.answer()

        if query.data == 'same_app':
            app = context.user_data.get('selected_app')
            if not app:
                return await main_menu(update, context)
            media_type = "screenshot/video" if app in SCREENSHOT_APPS else "video"
            await query.edit_message_text(
                f"📤 *Send proof for {app.upper()}*\n\n"
                f"Please send {media_type} with mobile number in caption\n"
                f"Example: `9876543210` (10 digits only, no spaces)",
                parse_mode='Markdown'
            )
            return ACTIVATION_PROOF

        apps = await read_apps()
        if not apps:
            await query.edit_message_text(
                "⚠️ No apps available for activation.",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🔙 Back", callback_data='back')]
                ])
            )
            return MAIN_MENU

        keyboard = [
            [InlineKeyboardButton(app['name'].upper(), callback_data=f"app_{app['name']}")]
            for app in apps
        ]
        keyboard.append([InlineKeyboardButton("🔙 Back", callback_data='back')])

        await query.edit_message_text(
            "📲 *Select application for activation:*",
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return APP_SELECTION
    except Exception as e:
        logger.error(f"Error in send_activation_proof: {e}")
        await handle_error(update, context)
        return MAIN_MENU

async def app_selected(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    try:
        query = update.callback_query
        await query.answer()
        
        app_name = query.data.replace('app_', '')
        context.user_data['selected_app'] = app_name
        
        media_type = "screenshot/video" if app_name in SCREENSHOT_APPS else "video"
        await query.edit_message_text(
            f"📤 *Send proof for {app_name.upper()}*\n\n"
            f"Please send {media_type} with mobile number in caption\n"
            f"Example: `9876543210` (10 digits only, no spaces)",
            parse_mode='Markdown'
        )
        return ACTIVATION_PROOF
    except Exception as e:
        logger.error(f"Error in app_selected: {e}")
        await handle_error(update, context)
        return MAIN_MENU

async def process_activation_proof(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Process submitted activation proof with channel forwarding"""
    try:
        app = context.user_data.get('selected_app')
        if not app:
            await update.message.reply_text("❌ No app selected. Please start over.")
            return MAIN_MENU

        # Validate media type
        if app in SCREENSHOT_APPS:
            if not (update.message.photo or update.message.video):
                await update.message.reply_text(f"❌ Please send a screenshot or video for {app.upper()}")
                return ACTIVATION_PROOF
        elif not update.message.video:
            await update.message.reply_text(f"❌ Please send a video for {app.upper()}")
            return ACTIVATION_PROOF

        # Validate mobile number
        if not update.message.caption:
            await update.message.reply_text("❌ Please include mobile number in caption")
            return ACTIVATION_PROOF

        mobile = update.message.caption.strip()
        if not re.fullmatch(r'\d{10}', mobile):
            await update.message.reply_text(
                "❌ *Invalid mobile number*\n\n"
                "Must be 10 digits without spaces.\n"
                "Example: `9876543210`",
                parse_mode='Markdown'
            )
            return ACTIVATION_PROOF

        email = context.user_data.get('email')
        if not email:
            await update.message.reply_text("❌ Session expired. Please /start again.")
            return ConversationHandler.END

        # Check for duplicates
        if await is_duplicate(app, mobile, email):
            await update.message.reply_text(
                f"❌ *Duplicate Activation*\n\n"
                f"This mobile number is already used for {app.upper()}",
                parse_mode='Markdown',
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🔄 Try Different App", callback_data='proof')],
                    [InlineKeyboardButton("🏠 Main Menu", callback_data='back')]
                ])
            )
            return MAIN_MENU

        # Record activation (status will be 'pending' by default)
        success = await write_activation(email, app, mobile)
        if not success:
            await update.message.reply_text("❌ Failed to record activation. Please try again.")
            return MAIN_MENU

        # Forward to channel with approval buttons
        channel_id = os.getenv('CHANNEL_ID')
        if channel_id:
            try:
                # Prepare caption
                caption = (
                    f"📬 *New Activation Request*\n\n"
                    f"📲 *App:* {app.upper()}\n"
                    f"📧 *User:* `{email}`\n"
                    f"📱 *Mobile:* `{mobile}`\n\n"
                    f"🔄 *Status:* ⏳ Pending"
                )

                # Prepare approval/rejection buttons
                keyboard = [
                    [
                        InlineKeyboardButton("✅ Approve", callback_data=f"approve_{email}_{app}_{mobile}"),
                        InlineKeyboardButton("❌ Reject", callback_data=f"reject_{email}_{app}_{mobile}")
                    ]
                ]

                # Add rejection reasons
                rejection_reasons = [
                    ["❌ Incorrect Proof (77)", f"reason_77_{email}_{app}_{mobile}"],
                    ["❌ Improper Activation (78)", f"reason_78_{email}_{app}_{mobile}"],
                    ["❌ Fraud Detected (79)", f"reason_79_{email}_{app}_{mobile}"],
                    ["❌ Wrong Device (80)", f"reason_80_{email}_{app}_{mobile}"],
                    ["❌ Late Submission (81)", f"reason_81_{email}_{app}_{mobile}"]
                ]

                if app == 'angelone':
                    keyboard.append([InlineKeyboardButton("✅ Non Trade Approved", callback_data=f"reason_nt_{email}_{app}_{mobile}")])

                for reason in rejection_reasons:
                    keyboard.append([InlineKeyboardButton(reason[0], callback_data=reason[1])])

                # Send to channel based on media type
                if update.message.video:
                    message = await context.bot.send_video(
                        chat_id=channel_id,
                        video=update.message.video.file_id,
                        caption=caption,
                        parse_mode='Markdown',
                        reply_markup=InlineKeyboardMarkup(keyboard)
                    )
                elif update.message.photo:
                    message = await context.bot.send_photo(
                        chat_id=channel_id,
                        photo=update.message.photo[-1].file_id,  # Highest resolution
                        caption=caption,
                        parse_mode='Markdown',
                        reply_markup=InlineKeyboardMarkup(keyboard)
                    )

                # Store message_id in database
                query = """
                UPDATE activations 
                SET message_id = ?
                WHERE email = ? AND app = ? AND mobile = ?
                """
                await execute_db_query(query, (message.message_id, email, app, mobile), commit=True)

            except Exception as e:
                logger.error(f"Failed to forward to channel: {e}")
                admin_id = os.getenv('ADMIN_CHAT_ID')
                if admin_id:
                    await context.bot.send_message(
                        chat_id=admin_id,
                        text=f"❌ Failed to forward activation:\n\nApp: {app}\nUser: {email}\nError: {e}"
                    )

        # Success response to user
        keyboard = [
            [InlineKeyboardButton("📤 Send Another (Same App)", callback_data='same_app')],
            [InlineKeyboardButton("📲 Select Another App", callback_data='proof')],
            [InlineKeyboardButton("🏠 Main Menu", callback_data='back')]
        ]

        await update.message.reply_text(
            "✅ *Activation submitted successfully!*\n\n"
            "You can check your status in the main menu.",
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return MAIN_MENU

    except Exception as e:
        logger.error(f"Error in process_activation_proof: {e}")
        await update.message.reply_text(
            "❌ *An error occurred*\n\n"
            "Please try again or contact support if the problem persists.",
            parse_mode='Markdown'
        )
        return MAIN_MENU

async def show_guide(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    try:
        query = update.callback_query
        await query.answer()

        guide = await read_guide()
        await query.edit_message_text(
            f"*{guide.get('title', 'Guide')}*\n\n{guide.get('content', 'Content not available')}",
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data='back')]
            ])
        )
        return MAIN_MENU
    except Exception as e:
        logger.error(f"Error in show_guide: {e}")
        await handle_error(update, context)
        return MAIN_MENU

async def show_rules(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    try:
        query = update.callback_query
        await query.answer()

        rules = await read_rules()
        await query.edit_message_text(
            f"*{rules.get('title', 'Rules')}*\n\n{rules.get('content', 'Content not available')}",
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data='back')]
            ])
        )
        return MAIN_MENU
    except Exception as e:
        logger.error(f"Error in show_rules: {e}")
        await handle_error(update, context)
        return MAIN_MENU

async def show_report_timing(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    try:
        query = update.callback_query
        await query.answer()

        apps = await read_apps(include_disabled=True)
        
        text = "⏰ *Report Timing Information*\n\n"
        
        for app in apps:
            status = f" ({STATUS_MESSAGES['enabled' if app['status'] == 0 else 'disabled']})"
            
            text += (
                f"📱 *{app['name'].upper()}*{status}\n"
                f"⏰ *Report Time:* {app['report_time']}\n"
                f"🔄 *Last Updated:* {app['report_updated']}\n\n"
            )

        await query.edit_message_text(
            text,
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data='back')]
            ])
        )
        return MAIN_MENU
    except Exception as e:
        logger.error(f"Error in show_report_timing: {e}")
        await handle_error(update, context)
        return MAIN_MENU

async def back_to_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    context.user_data.pop('status_offset', None)  # Reset pagination
    return await main_menu(update, context)

# --- Admin Functions ---
async def admin_mode_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if str(update.effective_user.id) != os.getenv('ADMIN_CHAT_ID'):
        await update.message.reply_text("❌ This command is for admin only.")
        return ConversationHandler.END

    context.user_data['admin_mode'] = True
    
    keyboard = [
        [InlineKeyboardButton("📝 Edit Reports", callback_data='edit_reports')],
        [InlineKeyboardButton("📲 Manage Apps", callback_data='manage_apps')],
        [InlineKeyboardButton("👤 Manage Users", callback_data='manage_users')],
        [InlineKeyboardButton("📂 Import Data", callback_data='import_data')],
        [InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')]
    ]

    await update.message.reply_text(
        "🛠 *Admin Mode Activated*\n\n"
        "Select an option from the menu below:",
        parse_mode='Markdown',
        reply_markup=InlineKeyboardMarkup(keyboard)
    )
    return ADMIN_MODE

async def admin_mode_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    if str(query.from_user.id) != os.getenv('ADMIN_CHAT_ID'):
        await query.edit_message_text("❌ Unauthorized access.")
        return ConversationHandler.END

    try:
        if query.data == 'manage_apps':
            keyboard = [
                [InlineKeyboardButton("⏰ Edit Report Time", callback_data='edit_app_time')],
                [InlineKeyboardButton("🔄 Toggle App Status", callback_data='toggle_app')],
                [InlineKeyboardButton("❌ Delete App", callback_data='delete_app')],
                [InlineKeyboardButton("📲 Add New App", callback_data='add_app')],
                [InlineKeyboardButton("🔙 Back to Admin", callback_data='back_admin')],
                [InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')]
            ]
            await query.edit_message_text(
                "📲 *Manage Apps*\n\n"
                "Select an option:",
                parse_mode='Markdown',
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
            return ADMIN_MODE
            
        elif query.data == 'edit_app_time':
            apps = await read_apps(include_disabled=True)
            keyboard = [
                [InlineKeyboardButton(app['name'].upper(), callback_data=f"edittime_{app['name']}")]
                for app in apps
            ]
            keyboard.append([InlineKeyboardButton("🔙 Back to Apps", callback_data='manage_apps')])
            keyboard.append([InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')])

            await query.edit_message_text(
                "⏰ *Edit App Report Time*\n\n"
                "Select app to edit:",
                parse_mode='Markdown',
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
            return ADMIN_MODE
            
        elif query.data.startswith('edittime_'):
            app_name = query.data.replace('edittime_', '')
            context.user_data['edit_app'] = app_name
            await query.edit_message_text(
                f"⏰ *Editing Report Time for {app_name.upper()}*\n\n"
                "Please send the new report time and updated date in format:\n\n"
                "`report_time`\n"
                "`report_updated`\n\n"
                "Example:\n"
                "`every 2 days`\n"
                "`16 July`",
                parse_mode='Markdown'
            )
            return EDIT_APP_MODE
            
        elif query.data == 'toggle_app':
            apps = await read_apps(include_disabled=True)
            keyboard = []
            
            for app in apps:
                current_status = app['status']
                action = "Disable" if current_status == 0 else "Enable"
                status_emoji = "🟢" if current_status == 0 else "🔴"
                keyboard.append([
                    InlineKeyboardButton(
                        f"{status_emoji} {app['name'].upper()} - {action}", 
                        callback_data=f"toggle_{app['name']}"
                    )
                ])
            
            keyboard.append([InlineKeyboardButton("🔙 Back to Apps", callback_data='manage_apps')])
            keyboard.append([InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')])

            await query.edit_message_text(
                "🔄 *Toggle App Status*\n\n"
                "Select app to enable/disable:",
                parse_mode='Markdown',
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
            return ADMIN_MODE
            
        elif query.data.startswith('toggle_'):
            app_name = query.data.replace('toggle_', '')
            success, message = await toggle_app_status(app_name)
            keyboard = [
                [InlineKeyboardButton("🔙 Back to Apps", callback_data='manage_apps')],
                [InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')]
            ]
            
            await query.edit_message_text(
                f"{'✅' if success else '❌'} {message}",
                parse_mode='Markdown',
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
            return ADMIN_MODE
            
        elif query.data == 'delete_app':
            apps = await read_apps(include_disabled=True)
            keyboard = [
                [InlineKeyboardButton(app['name'].upper(), callback_data=f"delapp_{app['name']}")]
                for app in apps
            ]
            keyboard.append([InlineKeyboardButton("🔙 Back to Apps", callback_data='manage_apps')])
            keyboard.append([InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')])

            await query.edit_message_text(
                "❌ *Delete App*\n\n"
                "Select app to delete:",
                parse_mode='Markdown',
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
            return ADMIN_MODE
            
        elif query.data.startswith('delapp_'):
            app_name = query.data.replace('delapp_', '')
            success, message = await delete_app(app_name)
            keyboard = [
                [InlineKeyboardButton("🔙 Back to Apps", callback_data='manage_apps')],
                [InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')]
            ]
            await query.edit_message_text(
                f"{'✅' if success else '❌'} {message}",
                parse_mode='Markdown',
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
            return ADMIN_MODE
            
        elif query.data == 'add_app':
            await query.edit_message_text(
                "📲 *Add New App*\n\n"
                "Please send the app name to add (lowercase, no spaces):\n\n"
                "Example: `newapp`",
                parse_mode='Markdown'
            )
            return ADD_APP_MODE
            
        elif query.data == 'manage_users':
            keyboard = [
                [InlineKeyboardButton("👤 Add User", callback_data='add_user')],
                [InlineKeyboardButton("❌ Delete User", callback_data='delete_user_prompt')],
                [InlineKeyboardButton("🔙 Back to Admin", callback_data='back_admin')],
                [InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')]
            ]
            await query.edit_message_text(
                "👤 *Manage Users*\n\n"
                "Select an option:",
                parse_mode='Markdown',
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
            return ADMIN_MODE
            
        elif query.data == 'add_user':
            await query.edit_message_text(
                "👤 *Add New User*\n\n"
                "Send user details in format:\n\n"
                "`email`\n"
                "`password`\n"
                "`name`\n\n"
                "For bulk add, separate users with blank lines:\n\n"
                "`email1`\n`password1`\n`name1`\n\n"
                "`email2`\n`password2`\n`name2`",
                parse_mode='Markdown'
            )
            return ADD_USER
            
        elif query.data == 'delete_user_prompt':
            await query.edit_message_text(
                "🗑 *Delete User Mode*\n\n"
                "Please send user credentials in format:\n\n"
                "`email@example.com`\n"
                "`password`\n\n"
                "For bulk delete, separate users with blank lines:\n\n"
                "`email1@example.com`\n`password1`\n\n"
                "`email2@example.com`\n`password2`\n\n"
                "Type /cancel to exit",
                parse_mode='Markdown'
            )
            return DELETE_USER_MODE
            
        elif query.data == 'edit_reports':
            keyboard = [
                [InlineKeyboardButton("📄 Download CSV", callback_data='download_csv')],
                [InlineKeyboardButton("📊 Download JSON", callback_data='download_json')],
                [InlineKeyboardButton("🗑 Delete Reports", callback_data='delete_reports')],
                [InlineKeyboardButton("🔄 Update Reports", callback_data='report_mode')],
                [InlineKeyboardButton("🔙 Back to Admin", callback_data='back_admin')],
                [InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')]
            ]
            await query.edit_message_text(
                "📝 *Manage Reports*\n\n"
                "Select an option:",
                parse_mode='Markdown',
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
            return ADMIN_MODE
            
        elif query.data == 'report_mode':
            await query.edit_message_text(
                "📝 *Report Update Mode*\n\n"
                "Send updates in format:\n\n"
                "`app_name`\n"
                "`mobile_number`\n"
                "`status` (approved/rejected)\n"
                "`reason` (optional)\n\n"
                "Multiple updates separated by blank lines.",
                parse_mode='Markdown'
            )
            return REPORT_MODE
            
        elif query.data == 'delete_reports':
            await query.edit_message_text(
                "🗑 *Delete Reports*\n\n"
                "Send deletions in format:\n\n"
                "`app_name`\n"
                "`mobile_number`\n\n"
                "Multiple deletions separated by blank lines.",
                parse_mode='Markdown'
            )
            return DELETE_REPORT_MODE
            
        elif query.data == 'download_json':
            await send_json_command(update, context)
            return ADMIN_MODE
            
        elif query.data == 'download_csv':
            await send_csv_command(update, context)
            return ADMIN_MODE
            
        elif query.data == 'import_data':
            keyboard = [
                [InlineKeyboardButton("👤 Import Users JSON", callback_data='import_users')],
                [InlineKeyboardButton("📊 Import Activations JSON", callback_data='import_activations')],
                [InlineKeyboardButton("🔙 Back to Admin", callback_data='back_admin')],
                [InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')]
            ]
            await query.edit_message_text(
                "📂 *Import Data*\n\n"
                "Select the type of data you want to import:",
                parse_mode='Markdown',
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
            return ADMIN_MODE
            
        elif query.data == 'import_users':
            context.user_data['import_type'] = 'users'
            await query.edit_message_text(
                "👤 *Import Users Data*\n\n"
                "Please send a JSON file containing users data.\n"
                "Expected format: Array of user objects with email, password, name fields.\n\n"
                "Duplicate entries will be automatically skipped.",
                parse_mode='Markdown'
            )
            return IMPORT_DATA_MODE
            
        elif query.data == 'import_activations':
            context.user_data['import_type'] = 'activations'
            await query.edit_message_text(
                "📊 *Import Activations Data*\n\n"
                "Please send a JSON file containing activations data.\n"
                "Expected format: Array of activation objects with email, app, mobile fields.\n\n"
                "Duplicate entries will be automatically skipped.",
                parse_mode='Markdown'
            )
            return IMPORT_DATA_MODE
            
        elif query.data == 'back_admin':
            # Return to main admin menu
            keyboard = [
                [InlineKeyboardButton("📝 Edit Reports", callback_data='edit_reports')],
                [InlineKeyboardButton("📲 Manage Apps", callback_data='manage_apps')],
                [InlineKeyboardButton("👤 Manage Users", callback_data='manage_users')],
                [InlineKeyboardButton("📂 Import Data", callback_data='import_data')],
                [InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')]
            ]

            await query.edit_message_text(
                "🛠 *Admin Mode Activated*\n\n"
                "Select an option from the menu below:",
                parse_mode='Markdown',
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
            return ADMIN_MODE
            
        elif query.data == 'cancel_admin':
            context.user_data.pop('admin_mode', None)
            await query.edit_message_text(
                "🚫 *Admin mode deactivated*",
                parse_mode='Markdown'
            )
            return ConversationHandler.END
            
    except Exception as e:
        logger.error(f"Error in admin_mode_handler: {e}")
        await handle_error(update, context)
        return ADMIN_MODE

async def import_data_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if not update.message.document:
            await update.message.reply_text("❌ Please send a JSON file.")
            return IMPORT_DATA_MODE

        file = await context.bot.get_file(update.message.document.file_id)
        file_name = update.message.document.file_name.lower()
        
        # Get predefined file type from context
        file_type = context.user_data.get('import_type')
        if not file_type:
            await update.message.reply_text(
                "❌ Import type not specified. Please start over from admin menu."
            )
            return ADMIN_MODE

        # Validate file extension
        if not file_name.endswith('.json'):
            await update.message.reply_text(
                "❌ Please send a JSON file only."
            )
            return IMPORT_DATA_MODE

        # Download and parse JSON file
        json_data = await file.download_as_bytearray()
        try:
            data = json.loads(json_data.decode('utf-8'))
            if not isinstance(data, list):
                raise ValueError("Expected JSON array")
        except Exception as e:
            await update.message.reply_text(f"❌ Invalid JSON file: {str(e)}")
            return IMPORT_DATA_MODE

        # Validate structure based on file type
        if file_type == 'users' and data:
            required_fields = ['email', 'password', 'name']
            if not all(field in data[0] for field in required_fields):
                await update.message.reply_text(
                    f"❌ Invalid users JSON structure. Required fields: {', '.join(required_fields)}"
                )
                return IMPORT_DATA_MODE
                
        elif file_type == 'activations' and data:
            required_fields = ['email', 'app', 'mobile']
            if not all(field in data[0] for field in required_fields):
                await update.message.reply_text(
                    f"❌ Invalid activations JSON structure. Required fields: {', '.join(required_fields)}"
                )
                return IMPORT_DATA_MODE

        # Import data
        result = await import_json_data(update, context, file_type, data)
        
        # Clear import type
        context.user_data.pop('import_type', None)
        
        # Show admin menu again
        keyboard = [
            [InlineKeyboardButton("📂 Import More Data", callback_data='import_data')],
            [InlineKeyboardButton("👤 Manage Users", callback_data='manage_users')],
            [InlineKeyboardButton("📝 Edit Reports", callback_data='edit_reports')],
            [InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')]
        ]

        await update.message.reply_text(
            f"📊 *Import Results*\n\n{result}",
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return ADMIN_MODE

    except Exception as e:
        logger.error(f"Error in import_data_handler: {e}")
        await update.message.reply_text(
            f"❌ Error importing data: {str(e)}",
            parse_mode='Markdown'
        )
        return IMPORT_DATA_MODE

async def edit_app_time_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        text = update.message.text.strip()
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        if len(lines) < 2:
            await update.message.reply_text(
                "❌ Invalid format. Please send:\n\n"
                "`report_time`\n"
                "`report_updated`",
                parse_mode='Markdown'
            )
            return EDIT_APP_MODE

        report_time = lines[0]
        report_updated = lines[1]
        app_name = context.user_data.get('edit_app')
        
        success, message = await update_app_time(app_name, report_time, report_updated)
        keyboard = [
            [InlineKeyboardButton("🔙 Back to Apps", callback_data='manage_apps')],
            [InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')]
        ]
        await update.message.reply_text(
            f"{'✅' if success else '❌'} {message}",
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return ADMIN_MODE
    except Exception as e:
        logger.error(f"Error in edit_app_time_handler: {e}")
        await handle_error(update, context)
        return ADMIN_MODE

async def add_app_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        app_name = update.message.text.strip().lower()
        success, message = await add_app(app_name)
        keyboard = [
            [InlineKeyboardButton("🔙 Back to Apps", callback_data='manage_apps')],
            [InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')]
        ]
        await update.message.reply_text(
            f"{'✅' if success else '❌'} {message}",
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return ADMIN_MODE
    except Exception as e:
        logger.error(f"Error in add_app_handler: {e}")
        await handle_error(update, context)
        return ADMIN_MODE

async def report_mode_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle report updates with proper validation"""
    try:
        text = update.message.text.strip()
        if not text:
            await update.message.reply_text("Please provide valid update data")
            return REPORT_MODE

        entries = [entry for entry in text.split('\n\n') if entry.strip()][:50]
        results = []

        for entry in entries:
            lines = [line.strip() for line in entry.split('\n') if line.strip()]
            if len(lines) < 3:
                results.append(f"❌ Invalid format: {entry[:30]}...")
                continue

            app = lines[0].lower()
            mobile = lines[1]
            status = lines[2].lower()
            reason = lines[3] if len(lines) > 3 else "0"

            if status not in ['approved', 'rejected']:
                results.append(f"❌ Invalid status '{status}' for {app} - {mobile}")
                continue

            # Find and update activation
            success = await update_activation("", app, mobile, status, reason)
            if success:
                results.append(f"✅ Updated {app} - {mobile} to {status}")
            else:
                results.append(f"❌ Failed to update {app} - {mobile}")

        keyboard = [
            [InlineKeyboardButton("🔙 Back to Reports", callback_data='edit_reports')],
            [InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')]
        ]
        await update.message.reply_text("\n".join(results), reply_markup=InlineKeyboardMarkup(keyboard))
        return ADMIN_MODE
    except Exception as e:
        logger.error(f"Error in report_mode_handler: {e}")
        await update.message.reply_text(
            "❌ Error processing updates. Please check format and try again.",
            parse_mode='Markdown'
        )
        return REPORT_MODE

async def delete_report_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        text = update.message.text.strip()
        if not text:
            await update.message.reply_text("Please provide valid deletion data")
            return DELETE_REPORT_MODE

        entries = [entry for entry in text.split('\n\n') if entry.strip()][:50]
        results = []

        for entry in entries:
            lines = [line.strip() for line in entry.split('\n') if line.strip()]
            if len(lines) < 2:
                results.append(f"❌ Invalid format: {entry[:30]}...")
                continue

            app = lines[0].lower()
            mobile = lines[1]

            deleted = await delete_activation(app, mobile)
            results.append(f"{'✅' if deleted else '❌'} Deleted {app} - {mobile}")

        keyboard = [
            [InlineKeyboardButton("🔙 Back to Reports", callback_data='edit_reports')],
            [InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')]
        ]
        await update.message.reply_text("\n".join(results), reply_markup=InlineKeyboardMarkup(keyboard))
        return ADMIN_MODE
    except Exception as e:
        logger.error(f"Error in delete_report_handler: {e}")
        await handle_error(update, context)
        return DELETE_REPORT_MODE

async def delete_user_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle user deletion with email/password input"""
    try:
        text = update.message.text.strip()
        if not text:
            await update.message.reply_text("Please provide valid user credentials")
            return DELETE_USER_MODE

        user_entries = [entry for entry in text.split('\n\n') if entry.strip()]
        results = []

        for entry in user_entries:
            lines = [line.strip() for line in entry.split('\n') if line.strip()]
            if len(lines) < 2:
                results.append(f"❌ Invalid format: {entry[:30]}...")
                continue

            email = lines[0].lower()
            password = lines[1]

            # Perform deletion
            deleted = await delete_user(email, password)
            if deleted:
                results.append(f"✅ Deleted user: {email}")
            else:
                results.append(f"❌ User not found or wrong password: {email}")

        # Prepare response
        response = "🗑 *Deletion Results*\n\n" + "\n".join(results)
        
        # Show admin menu again after completion
        keyboard = [
            [InlineKeyboardButton("👤 Manage Users", callback_data='manage_users')],
            [InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')]
        ]

        await update.message.reply_text(
            response,
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return ADMIN_MODE

    except Exception as e:
        logger.error(f"Error in delete_user_handler: {e}")
        await update.message.reply_text(
            "❌ Error processing deletion. Please try again.",
            parse_mode='Markdown'
        )
        return DELETE_USER_MODE

async def add_user_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        text = update.message.text.strip()
        if not text:
            await update.message.reply_text("Please provide valid user details")
            return ADD_USER

        user_entries = [entry for entry in text.split('\n\n') if entry.strip()][:20]
        results = []

        for entry in user_entries:
            parts = [p.strip() for p in entry.split('\n') if p.strip()]
            if len(parts) < 3:
                results.append(f"❌ Invalid format: {entry[:30]}...")
                continue

            email, password, name = parts[0], parts[1], ' '.join(parts[2:])
            success, message = await add_user(email, password, name)
            results.append(f"{'✅' if success else '❌'} {message}: `{email}`")

        keyboard = [
            [InlineKeyboardButton("👤 Manage Users", callback_data='manage_users')],
            [InlineKeyboardButton("🚫 Cancel Admin Mode", callback_data='cancel_admin')]
        ]
        await update.message.reply_text("\n".join(results), parse_mode='Markdown', reply_markup=InlineKeyboardMarkup(keyboard))
        return ADMIN_MODE
    except Exception as e:
        logger.error(f"Error in add_user_handler: {e}")
        await handle_error(update, context)
        return ADD_USER

async def send_json_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if str(update.effective_user.id) != os.getenv('ADMIN_CHAT_ID'):
            await update.message.reply_text("❌ This command is for admin only.")
            return

        # Create temporary JSON files from SQLite
        temp_files = []
        try:
            # Users JSON
            users = await execute_db_query("SELECT email, password, name, chat_id, created_at FROM users", fetch_all=True)
            users_file = "users_export.json"
            with open(users_file, 'w') as f:
                json.dump([dict(u) for u in users], f, indent=2)
            temp_files.append(users_file)
            
            # Activations JSON
            activations = await execute_db_query("SELECT * FROM activations", fetch_all=True)
            activations_file = "activations_export.json"
            with open(activations_file, 'w') as f:
                json.dump([dict(a) for a in activations], f, indent=2)
            temp_files.append(activations_file)
            
            # Apps JSON
            apps = await execute_db_query("SELECT * FROM apps", fetch_all=True)
            apps_file = "apps_export.json"
            with open(apps_file, 'w') as f:
                json.dump([dict(a) for a in apps], f, indent=2)
            temp_files.append(apps_file)
            
            # Send files
            for file in temp_files:
                with open(file, 'rb') as f:
                    await context.bot.send_document(
                        chat_id=update.effective_chat.id,
                        document=f,
                        filename=file,
                        caption=f'Here is the {file} export'
                    )
        finally:
            # Clean up temporary files
            for file in temp_files:
                if os.path.exists(file):
                    os.remove(file)

    except Exception as e:
        logger.error(f"Error in send_json_command: {e}")
        await update.message.reply_text("❌ Failed to generate JSON files. Check logs for details.")

async def send_csv_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if str(update.effective_user.id) != os.getenv('ADMIN_CHAT_ID'):
            await update.message.reply_text("❌ This command is for admin only.")
            return

        activation_csv, user_csv = await generate_csv_report()
        if not activation_csv or not user_csv:
            await update.message.reply_text("❌ No data available to generate CSV reports.")
            return

        try:
            await context.bot.send_document(
                chat_id=update.effective_chat.id,
                document=activation_csv.encode('utf-8'),
                filename=f'activations_report_{datetime.now().strftime("%Y%m%d")}.csv',
                caption='Activations report (CSV)'
            )
        except Exception as e:
            logger.error(f"Error sending activations CSV: {e}")

        try:
            await context.bot.send_document(
                chat_id=update.effective_chat.id,
                document=user_csv.encode('utf-8'),
                filename=f'users_report_{datetime.now().strftime("%Y%m%d")}.csv',
                caption='Users report (CSV)'
            )
        except Exception as e:
            logger.error(f"Error sending users CSV: {e}")

    except Exception as e:
        logger.error(f"Error in send_csv_command: {e}")
        await update.message.reply_text("❌ Failed to generate CSV reports. Check logs for details.")

async def admin_approve(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle approval from admin and edit original message"""
    try:
        query = update.callback_query
        await query.answer()

        _, email, app, mobile = query.data.split('_')
        
        # Update activation status in database
        await update_activation("", app, mobile, "approved")
        
        # Edit the original message with video/photo and remove buttons
        new_caption = (
            f"✅ *Approved Activation*\n\n"
            f"📲 *App:* {app.upper()}\n"
            f"📧 *User:* `{email}`\n"
            f"📱 *Mobile:* `{mobile}`\n\n"
            f"🔄 *Status:* ✅ Approved"
        )
        
        try:
            # Try to edit the caption (for video/photo messages)
            await query.edit_message_caption(
                caption=new_caption,
                parse_mode='Markdown'
            )
        except Exception as e:
            logger.error(f"Failed to edit message caption: {e}")
            try:
                # Fallback: try to edit as text message
                await query.edit_message_text(
                    text=new_caption,
                    parse_mode='Markdown'
                )
            except Exception as e2:
                logger.error(f"Failed to edit message text: {e2}")
                # Last resort: send a new message and delete old one
                try:
                    await context.bot.send_message(
                        chat_id=query.message.chat.id,
                        text=new_caption,
                        parse_mode='Markdown'
                    )
                    await context.bot.delete_message(
                        chat_id=query.message.chat.id,
                        message_id=query.message.message_id
                    )
                except Exception as e3:
                    logger.error(f"Failed to send replacement message: {e3}")

    except Exception as e:
        logger.error(f"Error in admin_approve: {e}")
        await query.answer("Failed to process approval", show_alert=True)

async def admin_reject(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle rejection from admin"""
    try:
        query = update.callback_query
        await query.answer()

        _, email, app, mobile = query.data.split('_')

        # Prepare rejection reasons
        rejection_reasons = [
            ["❌ Incorrect Proof (77)", f"reason_77_{email}_{app}_{mobile}"],
            ["❌ Improper Activation (78)", f"reason_78_{email}_{app}_{mobile}"],
            ["❌ Fraud Detected (79)", f"reason_79_{email}_{app}_{mobile}"],
            ["❌ Wrong Device (80)", f"reason_80_{email}_{app}_{mobile}"],
            ["❌ Late Submission (81)", f"reason_81_{email}_{app}_{mobile}"]
        ]

        keyboard = []
        for reason in rejection_reasons:
            keyboard.append([InlineKeyboardButton(reason[0], callback_data=reason[1])])

        if app == 'angelone':
            keyboard.append([InlineKeyboardButton("✅ Non Trade Approved", callback_data=f"reason_nt_{email}_{app}_{mobile}")])

        await query.edit_message_text(
            text=f"Select rejection reason for {app.upper()}:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )

    except Exception as e:
        logger.error(f"Error in admin_reject: {e}")
        await query.answer("Failed to process rejection", show_alert=True)

async def process_rejection(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Process specific rejection reason and edit original message"""
    try:
        query = update.callback_query
        await query.answer()

        parts = query.data.split('_')
        reason_id = parts[1]
        email = parts[2]
        app = parts[3]
        mobile = parts[4]

        reason_text = REJECTION_REASONS.get(reason_id, "Unknown reason")

        # Special case for Non Trade Approved
        if reason_id == 'nt':
            status = "approved"
            status_text = "Non Trade Approved"
            status_emoji = "✅"
        else:
            status = "rejected"
            status_text = "Rejected"
            status_emoji = "❌"

        # Update activation in database
        await update_activation("", app, mobile, status, reason_id)

        # Edit the original message with video/photo and remove buttons
        new_caption = (
            f"{status_emoji} *Activation {status_text}*\n\n"
            f"📲 *App:* {app.upper()}\n"
            f"📧 *User:* `{email}`\n"
            f"📱 *Mobile:* `{mobile}`\n\n"
            f"🔄 *Status:* {status_emoji} {status_text}\n"
            f"📝 *Reason:* {reason_text}"
        )

        try:
            # Try to edit the caption (for video/photo messages)
            await query.edit_message_caption(
                caption=new_caption,
                parse_mode='Markdown'
            )
        except Exception as e:
            logger.error(f"Failed to edit message caption: {e}")
            try:
                # Fallback: try to edit as text message
                await query.edit_message_text(
                    text=new_caption,
                    parse_mode='Markdown'
                )
            except Exception as e2:
                logger.error(f"Failed to edit message text: {e2}")
                # Last resort: send a new message and delete old one
                try:
                    await context.bot.send_message(
                        chat_id=query.message.chat.id,
                        text=new_caption,
                        parse_mode='Markdown'
                    )
                    await context.bot.delete_message(
                        chat_id=query.message.chat.id,
                        message_id=query.message.message_id
                    )
                except Exception as e3:
                    logger.error(f"Failed to send replacement message: {e3}")

    except Exception as e:
        logger.error(f"Error in process_rejection: {e}")
        await query.answer("Failed to process rejection reason", show_alert=True)

async def handle_error(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if update and update.callback_query:
            await update.callback_query.answer()
            await update.callback_query.edit_message_text(
                "❌ An error occurred. Please try again.",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🏠 Main Menu", callback_data='back')]
                ])
            )
        elif update and update.message:
            await update.message.reply_text(
                "❌ An error occurred. Please try again.",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🏠 Main Menu", callback_data='back')]
                ])
            )
    except Exception as e:
        logger.error(f"Error in handle_error: {e}")

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data.clear()
    await update.message.reply_text('Operation cancelled.')
    return ConversationHandler.END

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "ℹ️ *Help*\n\n"
        "Use /start to begin\n"
        "Use /menu to return to main menu\n"
        "Use /cancel to cancel current operation",
        parse_mode='Markdown'
    )

async def error(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.error(f"Update {update} caused error {context.error}")
    try:
        if update and update.callback_query:
            await update.callback_query.answer("An error occurred. Please try again.")
        elif update and update.message:
            await update.message.reply_text("An error occurred. Please try again.")
    except Exception as e:
        logger.error(f"Error in error handler: {e}")

def main() -> None:
    telegram_token = os.getenv('TELEGRAM_TOKEN')
    if not telegram_token:
        logger.error("TELEGRAM_TOKEN not found in environment variables.")
        return

    try:
        application = Application.builder().token(telegram_token).build()
        
        # Admin conversation handler
        admin_conv_handler = ConversationHandler(
            entry_points=[CommandHandler('adminmode', admin_mode_command)],
            states={
                ADMIN_MODE: [CallbackQueryHandler(admin_mode_handler)],
                ADD_APP_MODE: [MessageHandler(filters.TEXT & ~filters.COMMAND, add_app_handler)],
                EDIT_APP_MODE: [MessageHandler(filters.TEXT & ~filters.COMMAND, edit_app_time_handler)],
                REPORT_MODE: [MessageHandler(filters.TEXT & ~filters.COMMAND, report_mode_handler)],
                DELETE_REPORT_MODE: [MessageHandler(filters.TEXT & ~filters.COMMAND, delete_report_handler)],
                ADD_USER: [MessageHandler(filters.TEXT & ~filters.COMMAND, add_user_handler)],
                DELETE_USER_MODE: [MessageHandler(filters.TEXT & ~filters.COMMAND, delete_user_handler)],
                IMPORT_DATA_MODE: [
                    MessageHandler(filters.Document.ALL & filters.ChatType.PRIVATE, import_data_handler),
                    MessageHandler(filters.TEXT & ~filters.COMMAND, import_data_handler)
                ],
            },
            fallbacks=[CommandHandler('cancel', cancel)],
            per_message=False,
            per_chat=True,
            per_user=True,
        )

        # Main conversation handler
        conv_handler = ConversationHandler(
            entry_points=[CommandHandler('start', start)],
            states={
                EMAIL: [MessageHandler(filters.TEXT & ~filters.COMMAND, email_input)],
                PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, password_input)],
                MAIN_MENU: [
                    CallbackQueryHandler(activation_status, pattern='^status$'),
                    CallbackQueryHandler(send_activation_proof, pattern='^proof$'),
                    CallbackQueryHandler(show_guide, pattern='^guide$'),
                    CallbackQueryHandler(show_rules, pattern='^rules$'),
                    CallbackQueryHandler(show_report_timing, pattern='^report_timing$'),
                    CallbackQueryHandler(back_to_menu, pattern='^back$'),
                    CallbackQueryHandler(send_activation_proof, pattern='^same_app$'),
                    CallbackQueryHandler(handle_pagination, pattern='^(next_page|prev_page)$'),
                ],
                APP_SELECTION: [
                    CallbackQueryHandler(app_selected, pattern='^app_'),
                    CallbackQueryHandler(back_to_menu, pattern='^back$'),
                ],
                ACTIVATION_PROOF: [
                    MessageHandler(
                        (filters.VIDEO | filters.PHOTO) & filters.CAPTION,
                        process_activation_proof
                    ),
                    CallbackQueryHandler(back_to_menu, pattern='^back$'),
                ],
            },
            fallbacks=[CommandHandler('cancel', cancel)],
            per_message=False,
            per_chat=True,
            per_user=True,
        )

        # Add callback handlers for approval/rejection
        application.add_handler(CallbackQueryHandler(admin_approve, pattern='^approve_'))
        application.add_handler(CallbackQueryHandler(admin_reject, pattern='^reject_'))
        application.add_handler(CallbackQueryHandler(process_rejection, pattern='^reason_'))
        
        # Add handlers
        application.add_handler(CommandHandler('help', help_command))
        application.add_handler(CommandHandler('menu', menu_command))
        application.add_handler(admin_conv_handler)
        application.add_handler(conv_handler)
        application.add_error_handler(error)

        # Start the bot
        logger.info("Bot is now running and polling for updates...")
        application.run_polling(
            drop_pending_updates=True,
            allowed_updates=None,
            close_loop=True
        )
    except KeyboardInterrupt:
        logger.info("Bot stopped by user")
    except Exception as e:
        logger.error(f"Bot encountered an error: {e}")
    finally:
        logger.info("Bot shutdown complete")

if __name__ == '__main__':
    main()
