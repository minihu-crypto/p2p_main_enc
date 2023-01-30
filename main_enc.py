import pandas as pd
import numpy as np
from tqdm import tqdm
import socket
import json
import time
import struct
import sys
sys.path.append('./dkg_elgamal/build')
from dkg_elgamal import *
from zk import ZK, Proof


GROUP_ID = -1

# The distributed decryption has O(n^2) time complexity, so the whole procedure may take several hours.

# constant
EPOCH_NUM = 50_000
ERROR_THRESHOLD = 0.02  # this must be very small so that proof size can be less than 2KB, 0.02 is okay
# RANK1 cannot be smaller than 1e2 since alpha * RANK1 must be an integer
RANK1 = int(1e2)
RANK2 = int(5)  # This cannot be too large. Otherwise, power eq proof will exceed 2KB.
L1 = 15 # for power limit proof, this has to be large
L2 = 3 # for power eq proof
EPSILON1 = 10 # for power limit proof
EPSILON2 = int((2 ** (L2 - 1))) / RANK2 # for power eq proof


def alpha(_):
    return 0.01


def beta(k):
    return 0.1 / k ** 0.1


def eta(_):
    return 0.0005


def delta(_):
    return 1


def compute(p):
    return 0.5 * a * (p ** 2) + b * p


######################## 处理命令行参数 ########################
# 从命令行获取当前节点id
myid = int(sys.argv[1])
# 绑定的端口
port_base = 10000
myPort = port_base + myid
# 发电方数量
producerNum = int(sys.argv[2])
# 总节点列表
strArgs = sys.argv[3].replace('[',' ').replace(']',' ').replace(',',' ').split()
totalList = [int(i) for i in strArgs]
# 发电方列表
producerList = [totalList[i] for i in range(producerNum)]
# 用电方列表
consumerList = [totalList[i+producerNum] for i in range(len(totalList) - producerNum)]
# 总节点数
n = len(totalList)

# 读取输入数据
data = pd.read_csv('/data/csvdata/' + str(myid) + '.csv')
a = float(data['an'])
b = int(data['bn'])
lower = int(data['lower Pn'])
upper = int(data['upper Pn'])
producer = False
if lower == 0:
    producer = True


# 建立连接
# 还是一样p2p  所有节点进行通信  只修改ip和portbase
recv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
recv_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
if producer:
    recv_socket.bind(("192.168.60.11", myPort))
else:
    recv_socket.bind(("192.168.60.12", myPort))
recv_socket.listen(n-1)
recv_conn = list()
send_conn = dict()
# 处理连接, 两两建立连接
def idxToId(idx):
    if idx < len(producerList):
        return producerList[idx]
    else:
        return consumerList[idx-len(producerList)]
for i in range(n):
    if i < len(producerList):   # 发电方
        if producer and (idxToId(i) == myid):     # 是自己
            print("begin to recv conn ",idxToId(i) , myid, i)
            for j in range(n-1):
                print(j)
                connect, (host, myPort) = recv_socket.accept()
                recv_conn.append(connect)
            print("recv complete")
        else:   # 不是自己
            print("begin to send conn ", myid)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            send_conn[i] = sock
            while 1:
                try:
                    send_conn[i].connect(('192.168.60.11', port_base+idxToId(i)))  # 用来发送
                    break
                except:
                    continue
    else:                           # 用电方
        if (not producer) and idxToId(i) == myid:   # 是自己
            for j in range(n-1):
                connect, (host, myPort) = recv_socket.accept()
                recv_conn.append(connect)
        else:   # 自己是发电方
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            send_conn[i] = sock
            while 1:
                try:
                    send_conn[i].connect(('192.168.60.12', port_base+idxToId(i)))  # 用来发送
                    break
                except:
                    continue
print('connection success')
time.sleep(3)


################################# 通信模块函数 #################################

################################# 开始迭代 #################################
compute_start_time = time.time()

# 发送节点类型,ppk
C = np.empty(n, dtype=bool)
C[myid] = producer
psk = SharedSecretKey.create()
ppk = SharedPublickey.from_shared_secret_key(psk)
K = []
K.append(ppk)

for i in range(n):
    if i < len(producerList):   # 发电方
        if producer and (idxToId(i) == myid):     # 是自己
            print("begin to recv conn ",idxToId(i) , myid, i)
            for j in range(n-1):
                print(j)
                connect, (host, myPort) = recv_socket.accept()
                recv_conn.append(connect)
            print("recv complete")
        else:   # 不是自己
            print("begin to send conn ", myid)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            send_conn[i] = sock
            while 1:
                try:
                    send_conn[i].connect(('192.168.60.11', port_base+idxToId(i)))  # 用来发送
                    break
                except:
                    continue
    else:                           # 用电方
        if (not producer) and idxToId(i) == myid:   # 是自己
            for j in range(n-1):
                connect, (host, myPort) = recv_socket.accept()
                recv_conn.append(connect)
        else:   # 自己是发电方
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            send_conn[i] = sock
            while 1:
                try:
                    send_conn[i].connect(('192.168.60.12', port_base+idxToId(i)))  # 用来发送
                    break
                except:
                    continue
for j in range(n):
    if 1:# 当前应该接收
        for r in range(n-1):
            recv_msg_len = recv_conn[r].recv(4)
            msg_len = struct.unpack('i', recv_msg_len)[0]
            data = recv_conn[r].recv(msg_len)
            data = data.decode()
            data = json.loads(data)
            if (data["tag"] == "type and ppk"):
                id = data['id']
                C[id] = data['type']
                K.append(SharedPublickey.load(data['ppk']))
    elif idxToId(j) != myid:
        # 发送
        q = {
            "tag": "type and ppk",
            "id": myid,
            "type": producer,
            "ppk": ppk.save()
        }
        msg = json.dumps(q)
        encoded_msg = msg.encode()
        send_msg_len = struct.pack('i', len(encoded_msg))
        send_conn[j].send(send_msg_len)
        send_conn[j].send(encoded_msg)
        # print("send type and ppk complete")
    else:
        # 当前应该接收
        for r in range(n-1):
            recv_msg_len = recv_conn[r].recv(4)
            msg_len = struct.unpack('i', recv_msg_len)[0]
            data = recv_conn[r].recv(msg_len)
            data = data.decode()
            data = json.loads(data)
            if (data["tag"] == "type and ppk"):
                id = data['id']
                C[id] = data['type']
                K.append(SharedPublickey.load(data['ppk']))
PK = PublicKey.from_shared_public_keys(K)
# time.sleep(3)

# broadcast power limit
upper_random = Scalar.random()
upper_cipher = PK.encrypt_with_random(Scalar.from_i32(upper * RANK2), upper_random)
lower_random = Scalar.random()
lower_cipher = PK.encrypt_with_random(Scalar.from_i32(lower * RANK2), lower_random)
recv_upper = np.empty(n, dtype=Ciphertext)
recv_lower = np.empty(n, dtype=Ciphertext)
for j in range(n):
    if j != myid:
        # 发送
        q = {
            "tag": "limit",
            "id": myid,
            "upper": upper_cipher.save(),
            "lower": lower_cipher.save()
        }
        msg = json.dumps(q)
        encoded_msg = msg.encode()
        send_msg_len = struct.pack('i', len(encoded_msg))
        send_conn[j].send(send_msg_len)
        send_conn[j].send(encoded_msg)
        # print("send power limit complete")
    else:
        # 当前应该接收
        for r in range(n-1):
            recv_msg_len = recv_conn[r].recv(4)
            msg_len = struct.unpack('i', recv_msg_len)[0]
            data = recv_conn[r].recv(msg_len)
            data = data.decode()
            data = json.loads(data)
            if (data["tag"] == "limit"):
                id = data['id']
                recv_upper[id] = Ciphertext.load(data['upper'])
                recv_lower[id] = Ciphertext.load(data['lower'])

# initialize the coefficients
lambda_k = np.ones(n)
lmu_k = 0
umu_k = 0
p_k = np.zeros(n)
P_k = 0

sent_p = np.empty(n, dtype=Ciphertext)
power_in_p = np.empty(n, dtype=int)
random_in_p = np.empty(n, dtype=Scalar)
recv_lambda_k = np.empty((n, n), dtype=Ciphertext)
recv_p_k = np.empty((n, n), dtype=Ciphertext)


if myid == 0:
    bar = tqdm(range(1, EPOCH_NUM + 1))
else:
    bar = range(1, EPOCH_NUM + 1)
total_rounds = 0
for k in bar:
    # 把第k轮，把自己的lam和p先扩大RANK2倍，再加密
    lambda_k_raise = (lambda_k * RANK2).astype(int)
    p_k_raise = (p_k * RANK2).astype(int)
    lambda_k_cipher = np.empty(n, dtype=Ciphertext)
    p_k_cipher = np.empty(n, dtype=Ciphertext)
    for j in range(n):
        lambda_k_cipher[j] = PK.encrypt(Scalar.from_i32(lambda_k_raise[j]))
        rand = Scalar.random()
        p_k_cipher[j] = PK.encrypt_with_random(Scalar.from_i32(p_k_raise[j]), rand)
        sent_p[j] = p_k_cipher[j]
        power_in_p[j] = p_k_raise[j]
        random_in_p[j] = rand

    # 把lam和p广播出去
    for j in range(n * n):
        recv_node = j % n
        cipher_index = int(j / n)
        if recv_node != myid:
            # 发送
            recv_lambda_k[myid][cipher_index] = lambda_k_cipher[cipher_index]
            recv_p_k[myid][cipher_index] = p_k_cipher[cipher_index]
            q = {
                "tag": "lam_and_p",
                "id": myid,
                "lam": lambda_k_cipher[cipher_index].save(),
                "p": p_k_cipher[cipher_index].save()
            }
            msg = json.dumps(q)
            encoded_msg = msg.encode()
            send_msg_len = struct.pack('i', len(encoded_msg))
            send_conn[recv_node].send(send_msg_len)
            send_conn[recv_node].send(encoded_msg)
        else:
            # 当前应该接收
            for r in range(n-1):
                recv_msg_len = recv_conn[r].recv(4)
                msg_len = struct.unpack('i', recv_msg_len)[0]
                data = recv_conn[r].recv(msg_len)
                data = data.decode()
                data = json.loads(data)
                if (data["tag"] == "lam_and_p"):
                    id = data['id']
                    lam = Ciphertext.load(data['lam'])
                    p = Ciphertext.load(data['p'])
                    recv_lambda_k[id][cipher_index] = lam
                    recv_p_k[id][cipher_index] = p
    my_recv_lambda = recv_lambda_k[:, myid]
    my_recv_p = recv_p_k[:, myid]

    # p2p send lam and p
    # my_recv_lambda = np.empty(n, dtype=Ciphertext)
    # my_recv_p = np.empty(n, dtype=Ciphertext)
    # for j in range(n):
    #     if j != myid:
    #         # 发送
    #         q = {
    #             "tag": "lam_and_p",
    #             "id": myid,
    #             "lam": lambda_k_cipher[j].save(),
    #             "p": p_k_cipher[j].save()
    #         }
    #         msg = json.dumps(q)
    #         encoded_msg = msg.encode()
    #         send_msg_len = struct.pack('i', len(encoded_msg))
    #         send_conn[j].send(send_msg_len)
    #         send_conn[j].send(encoded_msg)
    #         # print("p2p send lam and p complete")
    #     else:
    #         # 当前应该接收
    #         for r in range(n-1):
    #             recv_msg_len = recv_conn[r].recv(4)
    #             msg_len = struct.unpack('i', recv_msg_len)[0]
    #             data = recv_conn[r].recv(msg_len)
    #             data = data.decode()
    #             data = json.loads(data)
    #             if (data["tag"] == "lam_and_p"):
    #                 id = data['id']
    #                 my_recv_lambda[id] = Ciphertext.load(data['lam'])
    #                 my_recv_p[id] = Ciphertext.load(data['p'])
    # print("lam and p already get!")
    # time.sleep(3)

    lambda_k_plus_one = np.ones(n, dtype=float)

    beta_k = int(beta(k) * RANK1)
    alpha_k = int(alpha(k) * RANK1)

    # compute the ciphertext to decrypt
    cipherList = np.empty(n, dtype=Ciphertext)
    for j in range(n):
        if producer == C[j]:
            cipherList[j] = PK.encrypt(Scalar.from_i32(0))
            continue
        second = PK.encrypt(Scalar.from_i32(int(lambda_k[j] * RANK2))) - my_recv_lambda[j]
        second = second * Scalar.from_i32(beta_k)
        third = PK.encrypt(Scalar.from_i32(int(p_k[j] * RANK2))) + my_recv_p[j]
        third = third * Scalar.from_i32(alpha_k)
        cipher = second + third
        cipherList[j] = cipher
    # for j in range(n):
    #     if type(cipherList[j]) != Ciphertext:
    #         print("cipher list error!")
    #         time.sleep(300)

    # print("cipher list formed!")
    # time.sleep(3)

    # broadcast all the ciphertexts
    recv_cipherList = np.empty((n, n), dtype=Ciphertext)
    for j in range(n):
        recv_cipherList[myid][j] = cipherList[j]
    for j in range(n * n):
        recv_node = j % n
        cipher_index = int(j / n)
        if recv_node != myid:
            # 发送
            q = {
                "tag": "ciphertext",
                "id": myid,
                "cipher": cipherList[cipher_index].save()
            }
            msg = json.dumps(q)
            encoded_msg = msg.encode()
            send_msg_len = struct.pack('i', len(encoded_msg))
            send_conn[recv_node].send(send_msg_len)
            send_conn[recv_node].send(encoded_msg)
        else:
            # 当前应该接收
            for r in range(n-1):
                recv_msg_len = recv_conn[r].recv(4)
                msg_len = struct.unpack('i', recv_msg_len)[0]
                data = recv_conn[r].recv(msg_len)
                data = data.decode()
                data = json.loads(data)
                if (data["tag"] == "ciphertext"):
                    id = data['id']
                    recv_c = Ciphertext.load(data['cipher'])
                    recv_cipherList[id][cipher_index] = recv_c
    # print("all ciphertexts get!")
    # time.sleep(3)

    # for i in range(n):
    #     for j in range(n):
    #         if type(recv_cipherList[i][i]) != Ciphertext:
    #             print("cipherList type error!")
    # print("cipherList type correct!")
    # time.sleep(3)

    # compute the decryption components
    dec_comp = np.empty((n,n), dtype=Point)
    for i in range(n):
        for j in range(n):
            dec_comp[i][j] = psk.decrypt_shared(recv_cipherList[i][j])
    # print("decryption components computed!")
    # time.sleep(3)

    # send decryption component
    recv_dec_comp = np.empty((n,n), dtype=Point) # (cipher_index, comp_index(id))
    for j in range(n):
        recv_dec_comp[j][myid] = dec_comp[myid][j]
    for j in range(n * n):
        recv_node = j % n
        comp_index = int(j / n)
        if recv_node != myid:
            # 发送
            q = {
                "tag": "dec_comp",
                "id": myid,
                "comp": dec_comp[recv_node][comp_index].save()
            }
            msg = json.dumps(q)
            encoded_msg = msg.encode()
            send_msg_len = struct.pack('i', len(encoded_msg))
            send_conn[recv_node].send(send_msg_len)
            send_conn[recv_node].send(encoded_msg)
        else:
            # 当前应该接收
            for r in range(n-1):
                recv_msg_len = recv_conn[r].recv(4)
                msg_len = struct.unpack('i', recv_msg_len)[0]
                data = recv_conn[r].recv(msg_len)
                data = data.decode()
                data = json.loads(data)
                if (data["tag"] == "dec_comp"):
                    id = data['id']
                    recv_comp = Point.load(data['comp'])
                    recv_dec_comp[comp_index][id] = recv_comp
    # print("all dec components get!")
    # time.sleep(3)

    # for i in range(n):
    #     for j in range(n):
    #         if type(recv_dec_comp[i][j]) != Point:
    #             print("dec_comp type error!")
    #             time.sleep(300)
    # print("dec_comp type correct!")
    # time.sleep(30)

    # decrypt and compute lambda_k+1
    for j in range(n):
        comp_j = []
        for r in range(n):
            if r != myid:
                comp_j.append(recv_dec_comp[j][r])
        result = psk.decrypt(cipherList[j], comp_j)
        # print("decryption success!")
        # time.sleep(3)
        result = discrete_log(result)
        # print("compute discrete log success! result: ", result)
        # time.sleep(3)
        result = result / (RANK1 * RANK2)
        lambda_k_plus_one[j] = lambda_k[j] -result

    umu_k_plus_one = max(0, umu_k + eta(k) * (P_k - upper))
    lmu_k_plus_one = max(0, lmu_k + eta(k) * (lower - P_k))

    p_k_plus_one = np.zeros(n, dtype=float)
    for j in range(n):
        if producer == C[j]:
            continue
        # 计算剩余的值
        p_k_plus_one[j] = (lambda_k_plus_one[j] -
                           umu_k_plus_one + lmu_k_plus_one - b) / a
        f_k = (abs(p_k[j]) + delta(k)) / (sum(abs(p_k)) + delta(k) * n)
        if producer == True:
            p_k_plus_one[j] = max(0, p_k[j] + f_k*(p_k_plus_one[j] - P_k))
        else:
            p_k_plus_one[j] = min(0, p_k[j] + f_k*(p_k_plus_one[j] - P_k))
        # print("compute end")


    if k % 100 == 0:
        # 终止条件
        p_error = abs(p_k - p_k_plus_one).max()
        lambda_error = abs(lambda_k - lambda_k_plus_one).max()
        mu_error = max(abs(lmu_k-lmu_k_plus_one), abs(umu_k-umu_k_plus_one))
        stop = False
        if max(p_error, lambda_error, mu_error) < ERROR_THRESHOLD:
            stop = True
        S = np.empty(n, dtype=bool)
        S[myid] = stop
        for j in range(n):
            if j != myid:
                q = {
                    "tag": "stop",
                    "id": myid,
                    "flag": stop
                }
                msg = json.dumps(q)
                encoded_msg = msg.encode()
                send_msg_len = struct.pack('i', len(encoded_msg))
                send_conn[j].send(send_msg_len)
                send_conn[j].send(encoded_msg)
            else:
                # 当前应该接收
                for r in range(n-1):
                    recv_msg_len = recv_conn[r].recv(4)
                    msg_len = struct.unpack('i', recv_msg_len)[0]
                    data = recv_conn[r].recv(msg_len)
                    data = data.decode()
                    data = json.loads(data)
                    # print(data)
                    if (data["tag"] == "stop"):
                        id = data['id']
                        S[id] = data['flag']
        if (False in S) == False:
            total_rounds = k
            break

        #####################################################
        # This is for debug use
        """
        p_error = abs(p_k - p_k_plus_one).max()
        lambda_error = abs(lambda_k - lambda_k_plus_one).max()
        mu_error = max(abs(lmu_k-lmu_k_plus_one), abs(umu_k-umu_k_plus_one))
        # print("my error: ", max(p_error, lambda_error, mu_error))
        E = np.empty(n, dtype=float)
        E[myid] = max(int(p_error * 10 ** 7), int(lambda_error * 10 ** 7), int(mu_error * 10 ** 7)) / 10 ** 7
        for j in range(n):
            if j != myid:
                q = {
                    "tag": "stop",
                    "id": myid,
                    "p_error": int(p_error * 10 ** 7),
                    "lambda_error": int(lambda_error * 10 ** 7),
                    "mu_error": int(mu_error * 10 ** 7)
                }
                msg = json.dumps(q)
                encoded_msg = msg.encode()
                send_msg_len = struct.pack('i', len(encoded_msg))
                send_conn[j].send(send_msg_len)
                send_conn[j].send(encoded_msg)
            else:
                # 当前应该接收
                for r in range(n-1):
                    recv_msg_len = recv_conn[r].recv(4)
                    msg_len = struct.unpack('i', recv_msg_len)[0]
                    data = recv_conn[r].recv(msg_len)
                    data = data.decode()
                    data = json.loads(data)
                    # print(data)
                    if (data["tag"] == "stop"):
                        id = data['id']
                        error = max(data['p_error'],
                                    data['lambda_error'], data['mu_error'])
                        E[id] = error / 10 ** 7
        print("error: ", E.max())
        if E.max() < ERROR_THRESHOLD:
            total_rounds = k
            break

        cost = compute(P_k)
        if myid == 0:
            total_cost = cost
            for i in range(n-1):
                recv_msg_len = recv_conn[i].recv(4)
                msg_len = struct.unpack('i', recv_msg_len)[0]
                data = recv_conn[i].recv(msg_len)
                data = data.decode()
                data = json.loads(data)
                total_cost += data["cost"]
            print("total cost: ", total_cost)
        else:
            msg = json.dumps({'cost': cost})
            encoded_msg = msg.encode()
            send_msg_len = struct.pack('i', len(encoded_msg))
            send_conn[0].send(send_msg_len)
            send_conn[0].send(encoded_msg)
        """
        ########################################################

    lambda_k = lambda_k_plus_one
    lmu_k = lmu_k_plus_one
    umu_k = umu_k_plus_one
    p_k = p_k_plus_one
    P_k = sum(p_k)

    # cost = compute(P_k)
    # print("lower and upper mu: ", lmu_k, umu_k)
    # print("lambda_k: ", lambda_k)
    # print("p_k: ", p_k)
    # print("P_k: ", P_k)
    # print("My cost: ", cost)

compute_end_time = time.time()
cost = compute(P_k)
print("lower and upper mu: ", lmu_k, umu_k)
print("lambda_k: ", lambda_k)
print("p_k: ", p_k)
print("P_k: ", P_k)
print("my cost: ", cost)
time.sleep(2) # must wait for other nodes to finish!!!
file = open('output/' + str(myid + 1) + '.txt', 'w')
file.write("compute time(s): " + str(compute_end_time - compute_start_time) + "\n")
file.write("\n")
file.write("power: " + str(p_k) + "\n")
file.write("my cost: " + str(cost) + "\n")

if myid == 0:
    total_cost = cost
    for i in range(n-1):
        recv_msg_len = recv_conn[i].recv(4)
        msg_len = struct.unpack('i', recv_msg_len)[0]
        data = recv_conn[i].recv(msg_len)
        data = data.decode()
        data = json.loads(data)
        total_cost += data["cost"]
    print("total cost: ", total_cost)
    file.write("total cost: " + str(total_cost) + "\n")
else:
    msg = json.dumps({'cost': cost})
    encoded_msg = msg.encode()
    send_msg_len = struct.pack('i', len(encoded_msg))
    send_conn[0].send(send_msg_len)
    send_conn[0].send(encoded_msg)

# generate zk proof

# power limit proof
file.write("\n")
file.write("power limit proof:\n")
prove_start_time = time.time()
E_epsilon1 = PK.encrypt_with_random(Scalar.from_i32(int(EPSILON1 * RANK2)), Scalar.from_i32(0))
z1 = ZK(L1)
total_power_cipher = sent_p[0]
total_power = power_in_p[0]
rand = random_in_p[0]
x = 0
for i in range(1,n):
    total_power_cipher = total_power_cipher + sent_p[i]
    total_power = total_power + power_in_p[i]
    rand = rand + random_in_p[i]
if producer:
    E = upper_cipher - total_power_cipher
    x = int(upper * RANK2) - total_power
    rand = upper_random - rand
else:
    E = total_power_cipher - lower_cipher
    x = total_power - int(lower * RANK2)
    rand = rand - lower_random
E = E + E_epsilon1
pi = z1.zk_prover(PK, E, x + int(EPSILON1 * RANK2), rand)
prove_end_time = time.time()
verify_start_time = time.time()
flag = z1.zk_verifier(PK, E, pi)
verify_end_time = time.time()
file.write(str(pi.save()) + "\n")
# file.write("prove time(s): " + str(prove_end_time - prove_start_time) + "\n")
# file.write("verify time(s): " + str(verify_end_time - verify_start_time) + "\n")
# file.write("proof size(bytes): " + str(pi.size) + "\n")
file.write("\n")


def save(path, evidence):
    out = open('/zkpevidence/{}/{}'.format(GROUP_ID, path))
    import struct
    for byte in evidence.save():
        out.write(struct.pack('B', byte))
    out.flush()
    out.close()

out = open('/log/{}/groupidprocess{}.log'.format(GROUP_ID, myid), 'w')
out.write('范围零知识证明生成开始时间戳: {}'.format(prove_start_time))
out.write('范围零知识证明生成结束时间戳: {}'.format(prove_end_time))
out.write('范围零知识证明验证开始时间戳: {}'.format(verify_start_time))
out.write('范围零知识证明验证结束时间戳: {}'.format(prove_end_time))
save('范围零知识证明', pi)

# transaction balance proof

# exchange p and rand
recv_plain_p = np.empty(n, dtype=int)
recv_rand = np.empty(n, dtype=Scalar)
for j in range(n):
    if j != myid:
        # 发送
        q = {
            "tag": "p and rand",
            "id": myid,
            "p": int(power_in_p[j]), # cannot omit int()
            "rand": random_in_p[j].save()
        }
        msg = json.dumps(q)
        encoded_msg = msg.encode()
        send_msg_len = struct.pack('i', len(encoded_msg))
        send_conn[j].send(send_msg_len)
        send_conn[j].send(encoded_msg)
        # print("send p and rand complete")
    else:
        # 当前应该接收
        for r in range(n-1):
            recv_msg_len = recv_conn[r].recv(4)
            msg_len = struct.unpack('i', recv_msg_len)[0]
            data = recv_conn[r].recv(msg_len)
            data = data.decode()
            data = json.loads(data)
            if (data["tag"] == "p and rand"):
                id = data['id']
                recv_plain_p[id] = data['p']
                recv_rand[id] = Scalar.load(data['rand'])

# producer generate eq proof
max_eq_error = 0
pi1 = 0
pi2 = 0
z2 = ZK(L2)
E_epsilon2 = PK.encrypt_with_random(Scalar.from_i32(int(EPSILON2 * RANK2)), Scalar.from_i32(0))
my_eq_proof = np.empty((n, 2), dtype=Proof)
if producer == True:
    file.write("power equivalence proof:\n")
    for j in range(n):
        if C[j] == False:
            file.write("generate eqivalence proof for node " + str(myid) + " and node " + str(j) + ":\n")
            prove_start_time = time.time()
            E = sent_p[j] + recv_p_k[j][myid]
            power = power_in_p[j] + recv_plain_p[j]
            rand = random_in_p[j] + recv_rand[j]
            max_eq_error = max(max_eq_error, abs(power))
            # file.write("max eq error: " + str(max_eq_error) + "\n")
            E1 = E_epsilon2 - E # not too large
            E2 = E + E_epsilon2 # not too small
            #
            # pi1 和 pi2
            pi1 = z2.zk_prover(PK, E1, int(EPSILON2 * RANK2) - power, Scalar.from_i32(0) - rand)
            pi2 = z2.zk_prover(PK, E2, power + int(EPSILON2 * RANK2), rand)
            prove_end_time = time.time()
            verify_start_time = time.time()
            flag1 = z2.zk_verifier(PK, E1, pi1)
            flag2 = z2.zk_verifier(PK, E2, pi2)
            verify_end_time = time.time()
            my_eq_proof[j][0] = pi1
            my_eq_proof[j][1] = pi2
            file.write(str(pi1.save()) + "\n")
            file.write(str(pi2.save()) + "\n")
            file.write("prove time(s): " + str(prove_end_time - prove_start_time) + "\n")
            file.write("verify time(s): " + str(verify_end_time - verify_start_time) + "\n")
            file.write("proof size of the transaction(bytes): " + str(pi1.size + pi2.size) + "\n")
            file.write("\n")
            out.write('第{}方与第{}方求和零知识证明生成开始时间戳: {}'.format(myid, j, prove_start_time))
            out.write('第{}方与第{}方求和零知识证明生成结束时间戳: {}'.format(myid, j, prove_end_time))
            out.write('第{}方与第{}方求和零知识证明验证开始时间戳: {}'.format(myid, j, verify_start_time))
            out.write('第{}方与第{}方求和零知识证明验证结束时间戳: {}'.format(myid, j, verify_end_time))
            save('第{}方与第{}方求和零知识证明1', pi1)
            save('第{}方与第{}方求和零知识证明2', pi2)
        else:
            my_eq_proof[j][0] = Proof(L2)
            my_eq_proof[j][1] = Proof(L2)
else:
    for j in range(n):
        my_eq_proof[j][0] = Proof(L2)
        my_eq_proof[j][1] = Proof(L2)

out.flush()
out.close()

# broadcast limit proofs
recv_limit_proof = np.empty(n, dtype=Proof)
recv_limit_proof[myid] = pi
for j in range(n):
    if j != myid:
        # 发送
        q = {
            "tag": "limit_proof",
            "id": myid,
            "limit_proof": pi.save()
        }
        msg = json.dumps(q)
        encoded_msg = msg.encode()
        send_msg_len = struct.pack('i', len(encoded_msg))
        send_conn[j].send(send_msg_len)
        send_conn[j].send(encoded_msg)
    else:
        # 当前应该接收
        for r in range(n-1):
            recv_msg_len = recv_conn[r].recv(4)
            msg_len = struct.unpack('i', recv_msg_len)[0]
            data = recv_conn[r].recv(msg_len)
            data = data.decode()
            data = json.loads(data)
            if (data["tag"] == "limit_proof"):
                id = data['id']
                p = Proof(L1)
                p.load(data['limit_proof'])
                recv_limit_proof[id] = p
# print("power limit proof broadcasted!")
# time.sleep(3)

# broadcast eq proofs
recv_eq_proof = np.empty((n, n, 2), dtype=Proof)
for j in range(n * n):
    recv_node = j % n
    proof_index = int(j / n)
    if recv_node != myid:
        # 发送
        recv_eq_proof[myid][proof_index][:] = my_eq_proof[proof_index][:]
        q = {
            "tag": "eq_proof",
            "id": myid,
            "p1": my_eq_proof[proof_index][0].save(),
            "p2": my_eq_proof[proof_index][1].save()
        }
        msg = json.dumps(q)
        encoded_msg = msg.encode()
        send_msg_len = struct.pack('i', len(encoded_msg))
        send_conn[recv_node].send(send_msg_len)
        send_conn[recv_node].send(encoded_msg)
    else:
        # 当前应该接收
        for r in range(n-1):
            recv_msg_len = recv_conn[r].recv(4)
            msg_len = struct.unpack('i', recv_msg_len)[0]
            data = recv_conn[r].recv(msg_len)
            data = data.decode()
            data = json.loads(data)
            if (data["tag"] == "eq_proof"):
                id = data['id']
                pi1 = Proof(L2)
                pi2 = Proof(L2)
                pi1.load(data['p1'])
                pi2.load(data['p2'])
                recv_eq_proof[id][proof_index][0] = pi1
                recv_eq_proof[id][proof_index][1] = pi2
# print("eq proof broadcasted!")
# time.sleep(3)

# for i in range(n):
#     for j in range(n):
#         for k in range(2):
#             if type(recv_eq_proof[i][j][k]) != Proof:
#                 print("eq_proof type error!")
#                 time.sleep(3000)
# print("eq_proof type correct")
# time.sleep(3)

# check proofs

# power limit check
flag = True
for i in range(n):
    if i == myid:
        continue
    E = recv_p_k[i][0]
    for j in range(1, n):
        E = E + recv_p_k[i][j]
    if C[i] == True:
        E = recv_upper[i] - E
    else:
        E = E - recv_lower[i]
    E = E + E_epsilon1
    if z1.zk_verifier(PK, E, recv_limit_proof[i]) == False:
        flag = False
print("power limit check: ", flag)
if flag == True:
    file.write("power limit check passed!\n")
else:
    file.write("power limit check not pass!\n")


# power eq check
flag = True
for i in range(n):
    if C[i] == False:
        continue
    for j in range(n):
        if C[j] == True:
            continue
        E = recv_p_k[i][j] + recv_p_k[j][i]
        E1 = E_epsilon2 - E # not too large
        E2 = E + E_epsilon2 # not too small
        if z2.zk_verifier(PK, E1, recv_eq_proof[i][j][0]) == False or z2.zk_verifier(PK, E2, recv_eq_proof[i][j][1]) == False:
            flag = False
print("power eq check: ", flag)
if flag == True:
    file.write("power equivalence check passed!\n")
else:
    file.write("power equivalence check not pass!\n")

file.close()
for conn in recv_conn:
    conn.close()
for key in send_conn.keys():
    send_conn[key].close()
recv_socket.close()

time.sleep(30000)
