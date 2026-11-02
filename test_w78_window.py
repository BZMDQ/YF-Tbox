"""单独入口：检查 0.8.32 及更早开发板的 16 KiB 帧兼容回退。"""
from test_w78_pipeline import test_old_16k_payload_pipeline_fallback


if __name__ == '__main__':
    test_old_16k_payload_pipeline_fallback()
    print('legacy 16 KiB protocol fallback passed')
