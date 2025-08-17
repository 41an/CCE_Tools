from PyQt5.QtWidgets import QMainWindow, QTabWidget
from PyQt5.QtCore import Qt, QTimer, QElapsedTimer
from ui.sm2_tab import SM2Tab
from ui.rsa_tab import RSATab
from ui.tools_tab import ToolsTab

# 模块注册：每个标签页标题 + 对应组件类
TABS = [
    ("SM2", SM2Tab),
    ("RSA", RSATab),
    ("TOOLS", ToolsTab)
]


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("密评小工具")
        self.resize(850, 1350)

        self.current_msg_format = "UTF-8"
        self.last_msg_format = "UTF-8"
        self.current_uid_format = "UTF-8"
        self.last_uid_format = "UTF-8"

        self.start_pos = None

        # 滑动节流控制
        self.last_scroll_direction = None
        self.scroll_cooldown_timer = QElapsedTimer()
        self.scroll_cooldown_active = False

        self.scroll_lock_active = False
        self.last_scroll_direction = None
        self.scroll_lock_timer = QTimer(self)
        self.scroll_lock_timer.setSingleShot(True)
        self.scroll_lock_timer.timeout.connect(self.release_scroll_lock)
        self.scroll_lock_interval = 50  # ms 冷却时间，可调节

        self.init_ui()

    def init_ui(self):
        self.tab_widget = QTabWidget()
        self.setCentralWidget(self.tab_widget)

        self.tab_widget.setTabPosition(QTabWidget.North)
        self.tab_widget.setMovable(False)
        self.tab_widget.setFocusPolicy(Qt.NoFocus)

        # 使用 TABS 列表统一添加页面
        for name, tab_class in TABS:
            self.tab_widget.addTab(tab_class(), name)

    def switch_tab(self, direction):
        current = self.tab_widget.currentIndex()
        total = self.tab_widget.count()

        if direction == "left":
            new_index = (current - 1 + total) % total
        elif direction == "right":
            new_index = (current + 1) % total
        else:
            return

        self.tab_widget.setCurrentIndex(new_index)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Right:
            self.switch_tab("right")
        elif event.key() == Qt.Key_Left:
            self.switch_tab("left")

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.start_pos = event.pos()

    def mouseReleaseEvent(self, event):
        if self.start_pos:
            end_pos = event.pos()
            delta_x = end_pos.x() - self.start_pos.x()
            threshold = 50

            if delta_x > threshold:
                self.switch_tab("left")
            elif delta_x < -threshold:
                self.switch_tab("right")

            self.start_pos = None

    def wheelEvent(self, event):
        delta_x = event.angleDelta().x()
        delta_y = event.angleDelta().y()

        if abs(delta_x) < 30 and abs(delta_y) < 30:
            return

        # 判断主滑动方向，要求水平滑动明显大于垂直滑动
        if abs(delta_x) > abs(delta_y) * 2:
            direction = "left" if delta_x > 0 else "right"
        else:
            event.ignore()
            return

        if not self.scroll_lock_active:
            # 第一次触发翻页
            self.trigger_tab_switch(direction)
        else:
            if direction != self.last_scroll_direction:
                # 方向变了，立刻触发翻页并重置冷却
                self.trigger_tab_switch(direction)
            else:
                # 同方向滑动，重置计时器延长冷却期，阻止多次翻页
                self.scroll_lock_timer.start(self.scroll_lock_interval)

    def trigger_tab_switch(self, direction):
        self.switch_tab(direction)
        self.last_scroll_direction = direction
        self.scroll_lock_active = True
        self.scroll_lock_timer.start(self.scroll_lock_interval)

    def release_scroll_lock(self):
        # 滑动结束，重置锁和方向
        self.scroll_lock_active = False
        self.last_scroll_direction = None

    def switch_tab(self, direction):
        current = self.tab_widget.currentIndex()
        total = self.tab_widget.count()
        if direction == "left":
            new_index = (current - 1 + total) % total
        elif direction == "right":
            new_index = (current + 1) % total
        else:
            return
        self.tab_widget.setCurrentIndex(new_index)