import os
import json
import logging
import base64
import requests
import asyncio
from datetime import datetime, timedelta
from functools import wraps
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, BotCommand
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    CallbackQueryHandler,
    filters
)

# --- 禁用SSL证书验证警告 ---
# --- Disable SSL certificate verification warnings ---
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- 基础配置 ---
# --- Basic Configuration ---
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
)
logging.getLogger("telegram.ext").addFilter(lambda record: "PTBUserWarning" not in record.getMessage())
logger = logging.getLogger(__name__)

# --- 全局变量和常量 ---
# --- Global Variables and Constants ---
CONFIG_FILE = 'config.json'
# --- 统一的状态定义 ---
# --- Unified State Definitions ---
(
    STATE_KKFOFA_MODE,
    STATE_KKFOFA_DATE,
    STATE_SETTINGS_MAIN,
    STATE_SETTINGS_ACTION,
    STATE_GET_KEY,
    STATE_GET_PROXY,
    STATE_REMOVE_API,
) = range(7)

# --- 权限与配置管理 ---
# --- Permissions and Configuration Management ---
def load_config():
    """加载配置文件，如果不存在则创建"""
    """Load configuration file, create if it does not exist"""
    default_config = {
        "apis": [],
        "admins": [int(base64.b64decode('NzY5NzIzNTM1OA==').decode('utf-8'))], # Default admin ID
        "proxy": "",
        "full_mode": False
    }
    if not os.path.exists(CONFIG_FILE):
        save_config(default_config)
        return default_config
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            # Ensure all keys exist, add if missing
            for key, value in default_config.items():
                config.setdefault(key, value)
            save_config(config)
            return config
    except (json.JSONDecodeError, IOError):
        logger.error("配置文件损坏或无法读取，将使用默认配置重建。")
        logger.error("Configuration file is corrupt or unreadable, rebuilding with default config.")
        save_config(default_config)
        return default_config

def save_config(config):
    """保存配置到文件"""
    """Save configuration to file"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

CONFIG = load_config()

# --- 装饰器 ---
# --- Decorators ---
def restricted(func):
    """装饰器：限制只有管理员才能访问"""
    """Decorator: Restrict access to administrators only"""
    @wraps(func)
    async def wrapped(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user_id = update.effective_user.id
        if user_id not in CONFIG.get('admins', []):
            message = "⛔️ 抱歉，您没有权限。"
            if update.callback_query:
                await update.callback_query.answer(message, show_alert=True)
            else:
                await update.message.reply_text(message)
            return ConversationHandler.END # 结束会话 | End the conversation
        return await func(update, context, *args, **kwargs)
    return wrapped

# --- Fofa 核心逻辑 ---
# --- Fofa Core Logic ---
HEADERS = { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/536.36" }

def _make_request(url: str):
    """发起网络请求的辅助函数"""
    """Helper function to make network requests"""
    proxies = {"http": CONFIG["proxy"], "https": CONFIG["proxy"]} if CONFIG.get("proxy") else None
    try:
        res = requests.get(url, headers=HEADERS, timeout=30, verify=False, proxies=proxies)
        res.raise_for_status()
        data = res.json()
        return data, data.get("errmsg")
    except requests.exceptions.RequestException as e:
        return None, f"网络请求失败: {e}"
    except json.JSONDecodeError:
        return None, "服务器返回非JSON格式。"

def verify_fofa_api(key):
    """验证 Fofa API Key 的有效性"""
    """Verify the validity of a Fofa API Key"""
    return _make_request(f"https://fofa.info/api/v1/info/my?key={key}")

def fetch_fofa_data(key, query, page=1, page_size=10000, fields="host"):
    """从 Fofa 获取数据"""
    """Fetch data from Fofa"""
    b64_query = base64.b64encode(query.encode('utf-8')).decode('utf-8')
    full_param = "&full=true" if CONFIG.get("full_mode", False) else ""
    url = f"https://fofa.info/api/v1/search/all?key={key}&qbase64={b64_query}&size={page_size}&page={page}&fields={fields}{full_param}"
    return _make_request(url)

async def get_best_api_key():
    """智能选择最佳 API Key"""
    """Intelligently select the best API Key"""
    if not CONFIG['apis']: return None, "没有配置API Key"
    tasks = [asyncio.to_thread(verify_fofa_api, key) for key in CONFIG['apis']]
    results = await asyncio.gather(*tasks)
    
    for i, (data, error) in enumerate(results):
        if not error and data.get('is_vip'):
            key = CONFIG['apis'][i]
            logger.info(f"✅ 找到VIP Key (用户: {data.get('username')})，优先使用。")
            return key, None
    
    if results and not results[0][1]:
        logger.info("ℹ️ 未找到VIP Key，使用第一个有效Key。")
        return CONFIG['apis'][0], None

    return None, results[0][1] or "所有API Key均无效"


# --- Bot 命令 & 对话流程 ---
# --- Bot Commands & Conversation Flow ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """处理 /start 命令"""
    """Handle the /start command"""
    await update.message.reply_text('👋 欢迎使用 Fofa 查询机器人！\n\n👇 点击 **菜单** 或输入 `/` 查看所有命令。', parse_mode=ParseMode.MARKDOWN)
    return ConversationHandler.END

@restricted
async def kkfofa_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """处理 /kkfofa 命令，开始查询流程"""
    """Handle the /kkfofa command to start the query process"""
    api_key, error = await get_best_api_key()
    if error:
        await update.message.reply_text(f"❌ 错误: {error}")
        return ConversationHandler.END

    query_text = " ".join(context.args)
    if not query_text:
        await update.message.reply_text("请输入查询语句，例如：`/kkfofa nezha`")
        return ConversationHandler.END

    msg = await update.message.reply_text("🔄 正在查询数据总数...")
    data, error = await asyncio.to_thread(fetch_fofa_data, api_key, query_text, 1, 1)

    if error:
        await msg.edit_text(f"❌ 查询出错: {error}")
        return ConversationHandler.END

    total_size = data.get('size', 0)
    if total_size == 0:
        await msg.edit_text("🤷‍♀️ 未找到相关结果。")
        return ConversationHandler.END
    
    context.user_data.update({'query': query_text, 'total_size': total_size, 'api_key': api_key, 'chat_id': update.effective_chat.id})

    if total_size <= 10000:
        await msg.edit_text(f"✅ 查询到 {total_size} 条结果，正在下载...")
        context.application.job_queue.run_once(run_full_download_query, 0, data=context.user_data)
        return ConversationHandler.END
    else:
        keyboard = [
            [InlineKeyboardButton("🗓️ 按天下载", callback_data='mode_daily'), InlineKeyboardButton("💎 全部下载", callback_data='mode_full')],
            [InlineKeyboardButton("❌ 取消", callback_data='mode_cancel')]
        ]
        await msg.edit_text(f"📊 查询到 {total_size} 条结果，已超出单次额度。\n请选择下载模式:", reply_markup=InlineKeyboardMarkup(keyboard))
        return STATE_KKFOFA_MODE

async def query_mode_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """处理下载模式选择按钮"""
    """Handle download mode selection buttons"""
    query = update.callback_query
    await query.answer()
    mode = query.data
    
    if mode == 'mode_daily':
        await query.edit_message_text("🗓️ 请输入起止日期 (格式: `YYYY-MM-DD to YYYY-MM-DD`)", parse_mode=ParseMode.MARKDOWN)
        return STATE_KKFOFA_DATE
    elif mode == 'mode_full':
        await query.edit_message_text(f"⏳ 已开始全量下载任务 ({context.user_data['total_size']}条)...")
        context.application.job_queue.run_once(run_full_download_query, 0, data=context.user_data)
    elif mode == 'mode_cancel':
        await query.edit_message_text("操作已取消。")
    return ConversationHandler.END

async def get_date_range_from_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """获取并处理用户输入的日期范围"""
    """Get and process the date range input by the user"""
    try:
        start_str, end_str = [s.strip() for s in update.message.text.lower().split("to")]
        start_date = datetime.strptime(start_str, "%Y-%m-%d")
        end_date = datetime.strptime(end_str, "%Y-%m-%d")

        if start_date > end_date:
            await update.message.reply_text("❌ 错误：开始日期不能晚于结束日期。")
            return STATE_KKFOFA_DATE

        await update.message.reply_text(f"✅ 日期范围确认！任务已在后台开始。")
        context.user_data.update({'start_date': start_date, 'end_date': end_date})
        context.application.job_queue.run_once(run_date_range_query, 0, data=context.user_data.copy())
        return ConversationHandler.END
    except (ValueError, IndexError):
        await update.message.reply_text("❌ 格式错误，请重新输入或 /cancel 取消。")
        return STATE_KKFOFA_DATE

@restricted
async def settings_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """处理 /settings 命令，显示主设置菜单"""
    """Handle the /settings command, display the main settings menu"""
    keyboard = [
        [InlineKeyboardButton("🔑 API 管理", callback_data='settings_api')],
        [InlineKeyboardButton("🌐 代理设置", callback_data='settings_proxy')]
    ]
    message_text = "⚙️ *设置菜单*"
    if update.callback_query:
        await update.callback_query.edit_message_text(message_text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.MARKDOWN)
    else:
        await update.message.reply_text(message_text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.MARKDOWN)
    return STATE_SETTINGS_MAIN

async def settings_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """处理主设置菜单的按钮点击"""
    """Handle button clicks in the main settings menu"""
    query = update.callback_query
    await query.answer()
    menu = query.data.split('_')[1]

    if menu == 'api':
        full_mode_text = "✅ 查询所有历史" if CONFIG.get("full_mode") else "⏳ 仅查近一年"
        keyboard = [
            [InlineKeyboardButton(f"时间范围: {full_mode_text}", callback_data='action_toggle_full')],
            [InlineKeyboardButton("➕ 添加", callback_data='action_add_api'), InlineKeyboardButton("➖ 删除", callback_data='action_remove_api')],
            [InlineKeyboardButton("🔙 返回", callback_data='action_back_main')]
        ]
        await query.edit_message_text("🔑 *API 管理*", reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.MARKDOWN)
        return STATE_SETTINGS_ACTION
    elif menu == 'proxy':
        keyboard = [
            [InlineKeyboardButton("✏️ 设置/更新", callback_data='action_set_proxy')],
            [InlineKeyboardButton("🗑️ 清除", callback_data='action_delete_proxy')],
            [InlineKeyboardButton("🔙 返回", callback_data='action_back_main')]
        ]
        await query.edit_message_text(f"🌐 *代理设置*\n当前: `{CONFIG.get('proxy') or '未设置'}`", reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.MARKDOWN)
        return STATE_SETTINGS_ACTION

async def settings_action_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """处理二级设置菜单中的具体操作"""
    """Handle specific actions in the sub-settings menus"""
    query = update.callback_query
    await query.answer()
    action = query.data.split('_', 1)[1]

    if action == 'back_main':
        return await settings_command(update, context)
    elif action == 'toggle_full':
        CONFIG["full_mode"] = not CONFIG.get("full_mode", False)
        save_config(CONFIG)
        query.data = 'settings_api'
        return await settings_callback_handler(update, context)
    elif action == 'add_api':
        await query.edit_message_text("请直接发送您的 Fofa API Key。")
        return STATE_GET_KEY
    elif action == 'remove_api':
        if not CONFIG['apis']:
            await query.edit_message_text("当前没有可删除的API Key。", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 返回", callback_data='settings_api')]]))
            return STATE_SETTINGS_MAIN
        msg = "请回复要删除的API Key编号:\n" + "\n".join([f"{i+1}. `{key[:4]}...`" for i, key in enumerate(CONFIG['apis'])])
        await query.edit_message_text(msg, parse_mode=ParseMode.MARKDOWN)
        return STATE_REMOVE_API
    elif action == 'set_proxy':
        await query.edit_message_text("请输入代理地址, 或 /cancel 取消。")
        return STATE_GET_PROXY
    elif action == 'delete_proxy':
        CONFIG['proxy'] = ""
        save_config(CONFIG)
        await query.edit_message_text("✅ 代理已清除。")
        await asyncio.sleep(1)
        return await settings_command(update, context)

async def get_key(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """获取并保存用户发送的 API Key"""
    """Get and save the API Key sent by the user"""
    key = update.message.text
    msg = await update.message.reply_text("正在验证...")
    data, error = await asyncio.to_thread(verify_fofa_api, key)
    if not error:
        if key not in CONFIG['apis']:
            CONFIG['apis'].append(key)
            save_config(CONFIG)
            await msg.edit_text(f"✅ 添加成功！你好, {data.get('username', 'user')}!")
        else:
            await msg.edit_text(f"ℹ️ 该Key已存在。")
    else:
        await msg.edit_text(f"❌ 验证失败: {error}")
    
    await asyncio.sleep(1.5)
    await settings_command(update, context)
    return ConversationHandler.END

async def get_proxy(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """获取并保存代理地址"""
    """Get and save the proxy address"""
    CONFIG['proxy'] = update.message.text
    save_config(CONFIG)
    await update.message.reply_text(f"✅ 代理已更新。")
    await asyncio.sleep(1)
    await settings_command(update, context)
    return ConversationHandler.END

async def remove_api(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """根据用户输入的编号移除 API Key"""
    """Remove an API Key based on the number input by the user"""
    try:
        index = int(update.message.text) - 1
        if 0 <= index < len(CONFIG['apis']):
            CONFIG['apis'].pop(index)
            save_config(CONFIG)
            await update.message.reply_text(f"✅ 已成功删除。")
        else:
            await update.message.reply_text("❌ 无效的编号。")
    except (ValueError, IndexError):
        await update.message.reply_text("❌ 请输入数字编号。")

    await asyncio.sleep(1)
    await settings_command(update, context)
    return ConversationHandler.END

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """取消当前操作"""
    """Cancel the current operation"""
    if update.callback_query:
        await update.callback_query.edit_message_text('操作已取消。')
    else:
        await update.message.reply_text('操作已取消。')
    context.user_data.clear()
    return ConversationHandler.END

# --- 后台任务 ---
# --- Background Tasks ---
async def run_full_download_query(context: ContextTypes.DEFAULT_TYPE):
    """执行全量下载任务"""
    """Execute the full download task"""
    job_data = context.job.data
    chat_id, query_text, total_size, api_key = job_data['chat_id'], job_data['query'], job_data['total_size'], job_data['api_key']
    output_filename = f"fofa_{datetime.now().strftime('%Y%m%d%H%M%S')}.txt"
    unique_results = set()
    msg = await context.bot.send_message(chat_id, "⏳ 开始全量下载...")
    
    pages_to_fetch = (total_size + 9999) // 10000
    for page in range(1, pages_to_fetch + 1):
        try: await msg.edit_text(f"下载进度: {page}/{pages_to_fetch}...")
        except: pass
        data, error = await asyncio.to_thread(fetch_fofa_data, api_key, query_text, page)
        if error:
            await context.bot.send_message(chat_id, f"❌ 第 {page} 页下载出错: {error}")
            continue
        unique_results.update(data.get('results', []))
            
    with open(output_filename, 'w', encoding='utf-8') as f: f.write("\n".join(unique_results))

    await msg.edit_text(f"✅ 下载完成！共 {len(unique_results)} 条。\n正在发送文件...")
    if os.path.getsize(output_filename) > 0:
        with open(output_filename, 'rb') as doc: await context.bot.send_document(chat_id, document=doc)
    else:
        await context.bot.send_message(chat_id, "🤷‍♀️ 任务完成，但文件为空。")
    os.remove(output_filename)

async def run_date_range_query(context: ContextTypes.DEFAULT_TYPE):
    """执行按天下载任务"""
    """Execute the daily download task"""
    job_data = context.job.data
    chat_id, base_query, start_date, end_date, api_key = job_data['chat_id'], job_data['query'], job_data['start_date'], job_data['end_date'], job_data['api_key']
    
    output_filename = f"fofa_{datetime.now().strftime('%Y%m%d%H%M%S')}.txt"
    unique_results = set()
    msg = await context.bot.send_message(chat_id, "⏳ 开始按天下载...")

    total_days = (end_date - start_date).days + 1
    for day_num, current_date in enumerate((start_date + timedelta(n) for n in range(total_days))):
        try: await msg.edit_text(f"下载进度: {day_num + 1}/{total_days} ({current_date.strftime('%Y-%m-%d')})...")
        except: pass
        
        # 根据Fofa客服说明，查询当天数据用 after:前一天
        # According to Fofa support, to query for a specific day, use after: a day before
        after_str = (current_date - timedelta(days=1)).strftime("%Y-%m-%d")
        query_for_day = f'({base_query}) && after="{after_str}"'
        page = 1
        while True:
            data, error = await asyncio.to_thread(fetch_fofa_data, api_key, query_for_day, page)
            if error:
                await context.bot.send_message(chat_id, f"❌ `{current_date.strftime('%Y-%m-%d')}` 下载出错: {error}")
                break
            results = data.get('results', [])
            if not results: break
            unique_results.update(results)
            if len(results) < 10000: break
            page += 1
            
    with open(output_filename, 'w', encoding='utf-8') as f: f.write("\n".join(unique_results))
    await msg.edit_text(f"✅ 下载完成！共 {len(unique_results)} 条(注意：结果为大于指定日期的集合)。\n正在发送文件...")
    if os.path.getsize(output_filename) > 0:
        with open(output_filename, 'rb') as doc: await context.bot.send_document(chat_id, document=doc)
    else:
        await context.bot.send_message(chat_id, "🤷‍♀️ 任务完成，但文件为空。")
    os.remove(output_filename)

# --- Bot 初始化 ---
# --- Bot Initialization ---
async def post_init(application: Application):
    """在Bot启动后执行的操作"""
    """Actions to perform after the bot starts"""
    await application.bot.set_my_commands([
        BotCommand("kkfofa", "🔍 资产搜索"),
        BotCommand("settings", "⚙️ 设置"),
        BotCommand("cancel", "❌ 取消操作"),
    ])
    logger.info("✅ 命令菜单已设置！")

def main():
    """主函数，启动Bot"""
    """Main function to start the bot"""
    try:
        # 建议将Token存储在环境变量中，而不是硬编码
        # It's recommended to store the Token in environment variables instead of hardcoding
        TELEGRAM_BOT_TOKEN = base64.b64decode('ODMyNTAwMjg5MTpBQUZyY1UzWExXYm02c0h5bjNtWm1GOEhwMHlRbHVUUXdaaw==').decode('utf-8')
    except Exception:
        logger.error("无法解码 Bot Token，请检查 Base64 编码。")
        return
        
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).post_init(post_init).build()

    # 统一的对话处理器
    # Unified conversation handler
    conv_handler = ConversationHandler(
        entry_points=[
            CommandHandler("start", start),
            CommandHandler("kkfofa", kkfofa_command),
            CommandHandler("settings", settings_command),
        ],
        states={
            STATE_KKFOFA_MODE: [CallbackQueryHandler(query_mode_callback, pattern="^mode_")],
            STATE_KKFOFA_DATE: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_date_range_from_message)],
            STATE_SETTINGS_MAIN: [CallbackQueryHandler(settings_callback_handler, pattern="^settings_")],
            STATE_SETTINGS_ACTION: [CallbackQueryHandler(settings_action_handler, pattern="^action_")],
            STATE_GET_KEY: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_key)],
            STATE_GET_PROXY: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_proxy)],
            STATE_REMOVE_API: [MessageHandler(filters.TEXT & ~filters.COMMAND, remove_api)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )
    
    application.add_handler(conv_handler)

    logger.info("🚀 机器人已启动...")
    application.run_polling()

if __name__ == '__main__':
    main()
