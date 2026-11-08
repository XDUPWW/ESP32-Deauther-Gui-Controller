"""生成项目自用的 LVGL 中文字库（专用子集）。

为什么不用 LVGL 自带的 CJK 子集：它按 ~1000 常用字打包，16px/4bpp 下要占 191 KB Flash；
本项目只需要"能看懂 SSID"，用几百个常用字 + SSID 领域词即可，体积可降到 ~40 KB。

用法（需要 Node + lv_font_conv）：
    npm install -g lv_font_conv
    python tools/gen_cjk_font.py

字体使用 Windows 自带的 Noto Sans SC（OFL 授权，可再分发）；字形栅格化成位图后
写入 components/wireless_ui/fonts/lv_font_ui_cjk.c，由 Kconfig 的
WIRELESS_UI_CJK_CUSTOM 打开。
"""

import glob
import io
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CHARSET = os.path.join(ROOT, "components", "wireless_ui", "fonts", "cjk_charset.txt")
OUTPUT = os.path.join(ROOT, "components", "wireless_ui", "fonts", "lv_font_ui_cjk.c")
FONT_CANDIDATES = [
    r"C:\Windows\Fonts\NotoSansSC-VF.ttf",
    r"C:\Windows\Fonts\Deng.ttf",
]

# 高频常用字（按使用频率大致排序，前 300 多个）
COMMON = (
    "的一是了我不人在他有这个上们来到时大地为子中你说生国年着就那和要她出也得里"
    "后自以会家可下而过天去能对小多然于心学么之都好看起发当没成只如事把还用第样"
    "道想作种开美总从无情己面最女但现前些所同日手又行意动方期它头经长儿回位分爱"
    "老因很给名法间斯知世什两次使身者被高已亲其进此话常与活正感见明问力理尔点文"
    "几定本公特做外孩相西果走将月十实向声车全信重三机工物气每并别真打太新比才便"
    "夫再书部水像眼等体却加电主界门利海受听表德少克代员许稀九区强放决干必战先则"
    "任取据处理技且马终拉格望觉术领共确传师观清今切院让识候带导争运笑飞风步改收"
    "根造言联持组济极林服快办议往元英士证近失转令准布始怎呢存未远叫台单影具罗字"
    "击流备兵连调深商算质团集百需价花党华城石级整府离况亚请际约示复病息究线似官"
    "火断精满支视消越器容照须增研写称企八功吗包片史委乎查轻易早曾除农找装广显阿"
    "李标谈吃图念六引历首医局突专费号尽另周较注语仅考落青随选列武红响虽推势参希"
    "古众构房半节土投某案黑维革划敌致陈律足态护七兴派孩验责营星够章音跟志底站严"
    "巴例防族供效续施留讲型料终答紧黄绝奇察母京段依批群项故按河米围江织害斗双境"
    "客纪采举杀攻父苏密低朝友诉止细愿千值仍男钱破网热助倒育属坐帝限船脸职速刻乐"
    "否刚威毛状率甚独球般普怕弹校苦创假久错承印晚兰试股拿脑预谁益阳若哪微尼继送"
    "急血惊伤素药适波夜省初喜卫源食险待述陆习置居劳财环排福纳欢雷警获模充负云停"
    "木游龙树疑层冷洲冲射略范竟句室异激汉村哈策演简卡罪判担州静退既衣您宗积余痛"
    "检差富灵协角占配征修皮挥胜降阶审沉坚善妈刘读超免压银买皇养伊怀执副乱抗犯追"
    "帮宣佛岁航优怪香著田铁控税左右份穿艺背阵草脚概恶块顿敢守酒岛托央户烈洋哥索"
    "胡款靠评版宝座释景顾弟登货互付伯慢欧换闻危忙核暗姐介坏讨丽良序升监临亮露永"
    "呼味野架域沙掉括舰鱼杂误湾吉减编楚肯测败屋跑梦散温困剑渐封救贵枪缺楼县尚毫"
    "移娘朋画班智亦耳恩短掌恐遗固席松秘谢鲁遇康虑幸均销钟诗藏赶剧票损忽巨炮旧端"
    "探湖录叶春乡附吸予礼港雨呀板庭妇归睛饭额含顺输摇招婚脱补谓油疗旅泽材灭逐莫"
    "笔亡鲜词圣择寻厂睡博烟授诺伦岸奥唐卖俄炸载洛健堂旁宫喝借君禁阴园谋宋避抓荣"
    "姑孙逃牙束跳顶玉镇雪午练爷篇肉嘴馆遍凡础洞卷坦牛宁纸诸训私庄祖丝翻暴森塔默"
    "握戏隐熟骨访弱蒙歌店鬼软典欲伙遭盘爸扩盖弄雄稳忘亿刺拥徒杨齐赛趣曲刀床迎冰"
    "虚玩析窗醒妻透购替塞休虎扬途刑绿兄迅套贸毕唯谷轮库迹尤竞街促延震弃甲伟麻川"
    "申缓潜闪售灯针哲络抵朱抱鼓植纯夏忍页杰筑折郑贝尊吴秀混臣雅振染盛怒舞圆搞狂"
    "措姓残秋培迷诚宽宇猛摆梅毁伸摩盟末乃悲拍丁赵硬麦蒋操耶阻订彩抽赞魔纷沿喊违"
    "妹浪汇币丰蓝殊献桌瓦莱援译夺汽烧距裁偏符勇触课敬哭懂墙袭召罚侠厅拜巧侧韩冒"
    "债曼融惯享戴童犹乘挂奖绍厚纵障讯涉彻刊丈爆乌役描洗患妙镜唱烦签仙彼弗症仿倾"
    "牌陷鸟轰咱菜闭奋庆撤泪茶疾缘播朗杜奶季丹狗尾仪偷奔珠虫驻孔宜艾桥淡翼恨繁寒"
    "伴叹旦愈潮粮缩罢聚径恰挑袋灰捕徐珍幕映裂泰隔启尖忠累炎暂估泛荒偿横拒瑞忆孤"
    "鼻闹羊呆厉衡胞零穷舍码赫婆灾洪腿胆津俗辩胸晓劲贫仁偶邦恢赖圈摸仰润堆碰艇稍"
    "迟辆废净凶署壁御奉旋冬矿抬蛋晨伏吹鸡倍糊秦盾杯租骑乏隆诊奴摄丧污渡旗甘耐凭"
    "扎抢绪粗肩梁幻菲皆碎宙叔岩荡综爬荷悉蒂返井壮薄悄扫敏碍殖详迪矛霍允幅撒剩凯"
    "颗骂赏液番箱贴漫酸郎腰舒眉忧浮辛恋餐吓挺励辞艘键伍峰尺昨黎辈贯侦滑券崇扰宪"
    "绕趋慈乔阅汗枝拖墨胁插箭腊粉泥氏彭拔骗凤慧媒佩愤扑龄驱惜豪掩兼跃尸肃帕驶堡"
    "届欣惠册储飘桑闲惨洁踪勃宾频仇磨递邪撞拟滚奏巡颜剂绩贡疯坡瞧截燃焦殿伪柳锁"
    "逼颇昏劝呈搜勤戒驾漂饮曹朵仔柔俩孟腐幼践籍牧凉牲佳娜浓芳稿竹腹跌逻垂遵脉貌"
    "柏狱猜怜惑陶兽帐饰贷昌叙躺钢沟寄扶铺邓寿惧询汤盗肥尝匆辉奈扣廷澳嘛董迁凝慰"
    "厌脏腾幽怨鞋丢埋泉涌辖躲晋紫艰魏吾慌祝邮吐狠鉴曰械咬邻赤挤弯椅陪割揭韦悟聪"
    "雾锋梯猫祥阔誉筹丛牵鸣沈阁穆屈旨袖猎臂蛇贺柱抛鼠瑟戈牢逊迈欺吨琴衰瓶恼燕仲"
    "诱狼池疼卢仗冠粒遥吕玄尘冯抚浅敦纠钻晶岂峡苍喷耗凌敲菌赔涂粹扁亏寂煤熊恭湿"
    "循暖糖赋抑秩帽哀宿踏烂袁侯抖夹昆肝擦猪炼恒慎搬纽纹玻渔磁铜齿跨押怖漠疲叛遣"
    "兹祭醉拳弥斜档稀捷肤疫肿豆削岗晃吞宏癌肚隶履涨耀扭坛拨沃绘伐堪仆郭牺歼墓雇"
    "廉契拼惩覆妖寂寞霾"
)

# Wi-Fi SSID 常见领域词
DOMAIN = (
    "华为小米红米荣耀中兴魅族联想戴尔惠普苹果三星一加真我努比亚摩托罗拉诺基亚索尼松下"
    "飞利浦美的格力海尔海信创维长虹康佳电信联通移动广电铁通长城宽带光猫路由无线网络"
    "信号密码访客来宾员工公共免费咖啡奶茶餐厅酒店宾馆公寓宿舍办公室会议室门店仓库前台"
    "客厅卧室主卧次卧书房厨房阳台卫生间洗手间儿童房老人房电脑手机平板电视空调冰箱洗衣"
    "扫地机器人门锁灯窗帘热水器光纤千兆百兆宽带测试临时共享家庭公司企业商店超市医院"
    "学校小区花园别墅楼层单元栋室号之与和大小新旧前后上下左右东西南北中国省市县区街路"
)


def observed_chars():
    """从历史扫描日志里抓 SSID 中真实出现过汉字。"""
    chars = set()
    for path in glob.glob(os.path.join(os.environ.get("TEMP", "."), "*.log")) + glob.glob(
        "/tmp/*.log"
    ):
        try:
            text = io.open(path, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        for line in text.splitlines():
            if not line.startswith("NET "):
                continue
            for ch in line:
                if "\u4e00" <= ch <= "\u9fff":
                    chars.add(ch)
    return chars


# 上限：400 个汉字 + ASCII。16px/4bpp 下约 40 KB 位图。
MAX_CJK_CHARS = 400


def build_charset():
    ordered = []
    seen = set()

    def push(chars):
        for ch in chars:
            if len(ordered) >= MAX_CJK_CHARS:
                return
            if ch not in seen:
                seen.add(ch)
                ordered.append(ch)

    # 优先保证本机实际出现过的 SSID 用字，再用高频字补齐
    push(sorted(observed_chars()))
    push(COMMON)
    push(DOMAIN)
    return "".join(ordered)


def main():
    if not os.path.isdir(os.path.dirname(CHARSET)):
        os.makedirs(os.path.dirname(CHARSET))
    charset = build_charset()
    io.open(CHARSET, "w", encoding="utf-8", newline="\n").write(charset)

    font = next((f for f in FONT_CANDIDATES if os.path.exists(f)), None)
    if font is None:
        print("找不到可用字体：", FONT_CANDIDATES)
        return 1

    tool = shutil.which("lv_font_conv") or shutil.which("lv_font_conv.cmd")
    if tool is None:
        print("找不到 lv_font_conv，请先 npm install -g lv_font_conv")
        return 1

    cmd = [
        tool,
        "--font", font,
        "--size", "16",
        "--bpp", "4",
        "--format", "lvgl",
        "--no-compress",
        "--lv-include", "lvgl.h",
        "--force-fast-kern-format",
        "--range", "0x20-0x7F",
        "--symbols", charset,
        "-o", OUTPUT,
    ]
    print(f"字体: {font}")
    print(f"字符数: {len(charset)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr)
        return result.returncode
    size = os.path.getsize(OUTPUT)
    print(f"生成: {OUTPUT} ({size / 1024:.1f} KB 源码)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
