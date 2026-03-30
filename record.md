  ### 实验记录
  #### 重定向链相关
  - 安全威胁
    - 在重定向链(HTTP 301/302)中是否存在从HTTPS->HTTP的情况？【协议降级攻击风险】
    - 重定向中的终点域名（或中间域名）是否存在过期、未注册之内的情况【攻击者抢注，接管邮件配置下发】
    - 返回的XML配置信息中的`redirectAddr`和`redirectUrl`中的重定向内容是否也存在如上的不安全问题【例如被恶意重定向到钓鱼域名】
  
  - 互联网宏观测量
    - 重定向链跳转次数？多次跳转到外部域名，不同域名间反复踢皮球
      - 直观展示：跳转次数CDF图展示重定向链长度的分布（分别绘制可以得到配置信息和不能的）
        - measurement/redirects_chain.py中NOTE TODO部分，可以做得更精确
      - 重定向跳转到外部第三方实体的
    - 各大TLD下邮件(配置)服务商的分布情况，量化邮件基础设施的中心化程度
      - 
      - 分析的时候发现存在部分域名同一机制下的不同路径得到配置信息的最终配置服务商不一致，于是单独进行了分析（measurement/find_intra_conflicts.py），在宏观测量的时候默认使用优先级最高的路径结果
    - 除了gTLD桑基图之外，引入国家顶级域，不同国家的隐私程度不同，重定向到本土邮件服务商/别国的邮件巨头

  - 错误配置
    - 反复重定向构成类似死循环
    - 机制冲突，不同机制最终重定向的服务商不一样？一种指向大型服务商，另一种指向一套本地cPanel服务器
      -  icloud.com comcast.net uol.com.br ya.ru xfinity.com
 

-  其他
   -  \u003cauthURL\u003ehttps://oauth.yandex.com/authorize\u003c/authURL\u003e\n    \u003ctokenURL\u003ehttps://oauth.yandex.com/token\u003c/tokenURL\u003e\n  \u003c/oAuth2\u003e\n\n  \u003cenable visiturl=\"http://mail.yandex.ru/neo/setup_client\"\u003e\n  