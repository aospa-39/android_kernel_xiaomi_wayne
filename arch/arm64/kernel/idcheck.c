#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/reboot.h>
#include <soc/qcom/socinfo.h>
#include <linux/net.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <asm/uaccess.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/kthread.h>

#include <crypto/hash.h>
#include <crypto/sha.h>
#include <crypto/md5.h>

#define PORT 8282

struct socket *sock;
struct task_struct *thread;

static inline __be32 in_aton_ipv4(const char *str) {
    int a, b, c, d;
    __be32 addr;

    if (sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
        return INADDR_NONE;
    }

    addr = htonl((a << 24) | (b << 16) | (c << 8) | d);
    return addr;
}

// "success"
//char success[] = "73HD75KS63YV63DH65JD73DH73";
char success[] = "prZZbpp";
// "fail"
//char fail[] = "66JD61GV69WB6C";
char fail[] = "cXfi";
// "150.158.163.179"
//char IP[] = "31IF35OB30IG2ESU31PF35QH38KF2EYV31EG36KD33TV2EKF31KF37DB39";
//char IP[] = "y2x8y258y308y46"; // 150.158.163.179 国内
 char IP[] = "148z0583081"; // 47.238.63.4 香港 金盾科技
// char IP[] = "108y268y1y8z0z"; // 43.159.141.232 美国
// "niganmaaiyou"
//char niganmaaiyou[] = "6EKF69FV67JF61RV6EOG6DPN61MF61YX69EV79OG6FSK75";
char niganmaaiyou[] = "kfdXkjXXfvlr";
// "jinitaimei"
//char jinitaimei[] = "6ALD69RB6EKS69SG74YW61QC69MX6DYS65OS69";
char jinitaimei[] = "gfkfqXfjbf";

int get_strings_sha256_hex(char *str, char *hex)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    char digest[32];
    int rc,i;

    /* Allocate a hash object */
    tfm = crypto_alloc_shash("sha256", 0, CRYPTO_ALG_ASYNC);
    if (IS_ERR(tfm)) {
        printk(KERN_ERR "Error %ld creating SHA256 object\n", PTR_ERR(tfm));
        return 1;
    }

    /* Allocate a hash descriptor */
    desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return 1;
    }

    /* Initialize the hash descriptor */
    desc->tfm = tfm;
    desc->flags = 0;

    /* Compute the hash */
    rc = crypto_shash_digest(desc, str, strlen(str), digest);
    if (rc != 0) {
        printk(KERN_ERR "Error %d computing SHA256 hash\n", rc);
        kfree(desc);
        crypto_free_shash(tfm);
        return 1;
    }

    /* Free the descriptor and the hash object */
    kfree(desc);
    crypto_free_shash(tfm);

    for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
        sprintf(&hex[i * 2], "%02x", digest[i]);
    }
    hex[SHA256_DIGEST_SIZE * 2] = '\0';

    return 0;
}

int get_strings_md5_hex(char *str, char *hex)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    char digest[32];
    int rc,i;

    /* Allocate a hash object */
    tfm = crypto_alloc_shash("md5", 0, CRYPTO_ALG_ASYNC);
    if (IS_ERR(tfm)) {
        printk(KERN_ERR "Error %ld creating MD5 object\n", PTR_ERR(tfm));
        return 1;
    }

    /* Allocate a hash descriptor */
    desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return 1;
    }

    /* Initialize the hash descriptor */
    desc->tfm = tfm;
    desc->flags = 0;

    /* Compute the hash */
    rc = crypto_shash_digest(desc, str, strlen(str), digest);
    if (rc != 0) {
        printk(KERN_ERR "Error %d computing MD5 hash\n", rc);
        kfree(desc);
        crypto_free_shash(tfm);
        return 1;
    }

    /* Free the descriptor and the hash object */
    kfree(desc);
    crypto_free_shash(tfm);

    for (i = 0; i < MD5_DIGEST_SIZE; i++) {
        sprintf(&hex[i * 2], "%02x", digest[i]);
    }
    hex[MD5_DIGEST_SIZE * 2] = '\0';

    return 0;
}

char *reverse_strings(char *str) {
    int len = strlen(str);
    int i;
    char temp;

    for (i = 0; i < len/2; i++) {
        temp = str[i];
        str[i] = str[len-i-1];
        str[len-i-1] = temp;
    }

    return str;
}

// 自定义映射表，只包含字母和数字
const char map123[] = "A.BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

// 获取字符在映射表中的索引
int get_index(char c) {
    int i;
    for (i = 0; i < 63; i++) {
        if (map123[i] == c) {
            return i;
        }
    }
    return -1; // 字符不在映射表中
}

// 加密函数
// void encrypt_string(char *input) {
//     int i;
//     for (i = 0; i < strlen(input); i++) {
//         int index = (get_index(input[i]) + 60) % 63;
//         input[i] = map123[index];
//     }
// }

// 解密函数
void decrypt_string(char *input) {
    int i;
    for (i = 0; i < strlen(input); i++) {
        int index = (get_index(input[i]) - 60 + 63) % 63;
        input[i] = map123[index];
    }
}


int get_token(char *str, char *toke) {
    char temp[strlen(str)];
    char md5_temp[MD5_DIGEST_SIZE * 2 + 1];
    strcpy(temp, str);
    reverse_strings(temp);
    //printk(KERN_INFO "reverse strings: %s\n", temp);
    if(get_strings_md5_hex(temp, md5_temp))
    {
        return 1;
    }
    if(get_strings_sha256_hex(md5_temp, toke))
    {
        return 1;
    }
    return 0;
}

int connect_to_server(void) {
    struct sockaddr_in saddr;
    int ret;
    ret = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
    if (ret < 0) {
        printk(KERN_ERR "IDCHECK: Error creating socket.\n");
        return -1;
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(PORT);
    saddr.sin_addr.s_addr = in_aton_ipv4(IP);

    ret = sock->ops->connect(sock, (struct sockaddr *)&saddr, sizeof(saddr), 0);
    printk(KERN_INFO "IDCHECK: connect result: %d\n", ret);

    if (ret < 0) {
        printk(KERN_ERR "IDCHECK: Error connecting to server.\n");
        return -1;
    }

    return 0;
}

int send_http_request(char *serial) {
    char request[512];
    int ret;
    struct msghdr msg;
    struct kvec vec;
    int len = 0;

    char token[SHA256_DIGEST_SIZE * 2 + 1];
    char temp_serial[128];
    strcpy(temp_serial, serial);
    strcat(temp_serial, jinitaimei);
    get_token(temp_serial, token);

    sprintf(request, "GET /?str=%s&token=%s HTTP/1.1\r\nHost: %s\r\n\r\n", serial, token, IP);
    len = strlen(request);

    //printk(KERN_INFO "http: %s\n", request);

    vec.iov_base = request;
    vec.iov_len = len;

    memset(&msg, 0, sizeof(msg));

    ret = kernel_sendmsg(sock, &msg, &vec, 1, len);
    if (ret < 0) {
        printk(KERN_ERR "IDCHECK: Error sending request.\n");
        return -1;
    }

    return 0;
}

int receive_response(char *response) {
    char rbuf[1024];
    int ret;
    struct msghdr msg;
    struct kvec vec;
    //int len = 0;

    vec.iov_base = rbuf;
    vec.iov_len = sizeof(rbuf);

    memset(&msg, 0, sizeof(msg));

    ret = kernel_recvmsg(sock, &msg, &vec, 1, sizeof(rbuf), 0);
    if (ret < 0) {
        printk(KERN_ERR "IDCHECK: Error receiving response.\n");
        return -1;
    }

    strcpy(response, rbuf);
    return 0;
}

void close_connection(void) {
    sock_release(sock);
}

int check_response(char *response, char *serial) {
    char temp[strlen(success) + strlen(serial) + strlen(niganmaaiyou)];
    char token[SHA256_DIGEST_SIZE * 2 + 1];

    strcpy(temp, success);
    strcat(temp, serial);
    strcat(temp, niganmaaiyou);

    //printk(KERN_INFO "check str: %s\n", temp);

    get_token(temp, token);

    //printk(KERN_INFO "check token: %s\n", token);

    if(strstr(response, token) == NULL){
        return 1;
    }
    return 0;
}

static int thread_function(void *data)
{
    long serial;
    char serial_str[20];
    char response[1024];
    int ret;
    long fuzz_value;

    // 等待10分钟 时间
    msleep(10 * 60 * 1000);

    // 在这里执行你想要的任务
    fuzz_value = 0x12345678;
    serial = socinfo_get_serial_number() ^ fuzz_value;
    sprintf(serial_str, "%ld", serial);
    printk(KERN_INFO "IDCHECK: Serial str: %s\n", serial_str);

    ret = connect_to_server();
    if (ret < 0) {
        orderly_poweroff(true);
        //ctrl_alt_del();
    }

    ret = send_http_request(serial_str);
    if (ret < 0) {
        close_connection();
        orderly_poweroff(true);
        //ctrl_alt_del();
    }

    ret = receive_response(response);
    if (ret < 0) {
        close_connection();
        orderly_poweroff(true);
        //ctrl_alt_del();
    }

    ret = check_response(response, serial_str);
    if (ret < 0) {
        printk(KERN_INFO "111.\n");
        close_connection();
        orderly_poweroff(true);
        //ctrl_alt_del();
    } else if (ret == 1) {
        close_connection();
        printk(KERN_INFO "IDCHECK NOT MATCH.\n");
        orderly_poweroff(true);
        //ctrl_alt_del();
    } else {
        close_connection();
        printk(KERN_INFO "IDCHECK MATCHED.\n");
        return 0;
    }
    return 1;
}

static int __init my_module_init(void) {
    decrypt_string(success);
    decrypt_string(fail);
    decrypt_string(IP);
    decrypt_string(niganmaaiyou);
    decrypt_string(jinitaimei);
    printk(KERN_INFO "IDCHECK: success: %s\n", success);
    printk(KERN_INFO "IDCHECK: fail: %s\n", fail);
    printk(KERN_INFO "IDCHECK: IP: %s\n", IP);
    printk(KERN_INFO "IDCHECK: niganmaaiyou: %s\n", niganmaaiyou);
    printk(KERN_INFO "IDCHECK: jinitaimei: %s\n", jinitaimei);

    // 创建线程
    thread = kthread_create(thread_function, NULL, "my_thread");
    if (IS_ERR(thread)) {
        printk(KERN_INFO "IDCHECK: Error creating thread.\n");
        return PTR_ERR(thread);
    }

    // 启动线程
    wake_up_process(thread);

    return 0;
}

static void __exit my_module_exit(void) {
    // 终止线程
    kthread_stop(thread);
}

module_init(my_module_init);
module_exit(my_module_exit);
