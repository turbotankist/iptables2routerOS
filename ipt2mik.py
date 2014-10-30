#iptables2mikrotik
#by A.Lazarev

#замена двоеточия на тире между номерами
def colon2dash(word):
    if ':' in word:
        return word.replace(':','-')
    else: return word;
def colon2port(word):
    if ':' in word:
        return word.replace(':',' to-ports=')
    else: return word;

#парсинг параметров 
def pars(obj,symb):
    try:
        result=obj[obj.index(symb)+1]
        if obj[obj.index(symb)-1]!='!':
            if result=='!': result=result+obj[obj.index(symb)+2]
        else: result='!'+result.replace(',',',!') #в нашем случае для tcp-flag 
        return result
    except: return  False 
        
    
#класс определяющий каждую строку-правило
class RULE:
    def __init__(self, tab_line):
        self.line=tab_line.split()
    def chain(self):
        return self.line[self.line.index('-A')+1].lower()
    def nat_chain(self):
        if self.line[1]=='PREROUTING':
            return 'dstnat'
        elif self.line[1]=='POSTROUTING':
            return 'srcnat'
        else: return self.line[1].lower()
    def prot(self):
        return pars(self.line,'-p')
    def srs_a(self):
        return pars(self.line,'-s')
    def dst_a(self):
        return pars(self.line,'-d')
    def in_int(self):
        return pars(self.line,'-i')
    def out_int(self):
        return pars(self.line,'-o')
    def flags(self):
        return pars(self.line,'--tcp-flags')
    def state(self):
        return pars(self.line,'--state') 
    def dst_p(self):
        try:
            if '--dports' in self.line:
                return self.line[self.line.index('--dports')+1]
            else: return self.line[self.line.index('--dport')+1]
        except: return  False
    def src_p(self):
        try:
            if '--sports' in self.line:
                return self.line[self.line.index('--sports')+1]
            else: return self.line[self.line.index('--sport')+1]
        except: return  False;
    def nat_ad(self):
        try:
            if '--to-destination' in self.line:
                return self.line[self.line.index('--to-destination')+1]
            else: return self.line[self.line.index('--to-source')+1]
        except: return  False;
        
    def comm(self): #обработка комментария в правиле
        try:
            i=self.line.index('--comment')+1
            ful_com=self.line[i]
            while ful_com[-1]!='"':
                ful_com=ful_com+' '+self.line[i+1]
                i+=1
            return ful_com
        except: return  False
    def action(self): #выбор действия на правило
        try:
            if self.line[self.line.index('-j')+1]=='DROP': return 'drop'
            elif self.line[self.line.index('-j')+1]=='ACCEPT': return 'accept'
            elif self.line[self.line.index('-j')+1]=='REJECT': return 'reject reject-with='+self.line[self.line.index('--reject-with')+1]
            elif self.line[self.line.index('-j')+1]=='RETURN': return 'return'
            elif self.line[self.line.index('-j')+1]=='LOG': return 'log'
            elif self.line[self.line.index('-j')+1]=='DNAT': return 'dst-nat'
            elif self.line[self.line.index('-j')+1]=='SNAT': return 'src-nat'
            else :return 'jump jump-target='+self.line[self.line.index('-j')+1].lower()
        except: return  False

#начало программы
        
def iptab2mikr(IPTABLES,file):

    mik_list=''
    nxt=True
    if file:   #если обрабатываем файл 
        try: f_ipt=open(IPTABLES)
        except:
            print("file "+IPTABLES+" not exist")
            return 0
        nat=False
        x='abc'

    else:   #если обрабатываем введённую команду
        x=IPTABLES
        if 'iptables -A' in x: x=x[9:];
        if '-t nat' in x: nat=True; mik_list=mik_list+'ip firewall nat\n'
        else: nat=False; mik_list=mik_list+'ip firewall filter\n'
    
    while x and nxt:    
        if file: x=f_ipt.readline()
        else: nxt=False
        
        if  x[:2]=='-A':
            print(x)
            y=RULE(x)
            if nat: mikr="add chain="+y.nat_chain();
            else: mikr="add chain="+y.chain();
            if y.prot(): mikr=mikr+" protocol="+y.prot();
            if y.srs_a(): mikr=mikr+" src-address="+y.srs_a();
            if y.dst_a(): mikr=mikr+" dst-address="+y.dst_a();
            if y.dst_p(): mikr=mikr+" dst-port="+colon2dash(y.dst_p());
            if y.src_p(): mikr=mikr+" src-port="+colon2dash(y.src_p());
            if y.flags(): mikr=mikr+" tcp-flags="+y.flags().lower();
            if y.state(): mikr=mikr+" connection-state="+y.state().lower();
            if y.in_int(): mikr=mikr+" in-interface="+y.in_int().replace('eth0.','vlan');
            if y.out_int(): mikr=mikr+" out-interface="+y.out_int().replace('eth0.','vlan');
            if y.action(): mikr=mikr+" action="+y.action();
            if y.nat_ad(): mikr=mikr+" to-addresses="+colon2port(y.nat_ad());
            if y.comm(): mikr=mikr+" comment="+y.comm();
            mik_list=mik_list+mikr+'\n'
            print(mikr)
        elif '*filter' in x:
            nat=False
            mik_list=mik_list+'ip firewall filter\n'
          #  print(mikr)
        elif '*mangle' in x:
            nat=False
            mik_list=mik_list+'ip firewall mangle\n'
          #  print(mikr)
        elif '*nat' in x:
            nat=True
            mik_list=mik_list+'ip firewall nat\n'
           # print(mikr)      
    f_mik=open('routos.txt','w')
    f_mik.write(mik_list)
    f_mik.close()
    if file: f_ipt.close()
    return 1

if __name__=="__main__":
    ch=1
    while ch!=3:
        print("make your choice\n1 - iptables file\n2 - manual input commands\n3 - Cancel\n")
        ch=input()
        if ch=='1':
            if iptab2mikr('iptables.txt',True):
                print("\n\nготово - файл routos.txt");
                break
        elif ch=='2':
            print("Введите требуемую команду iptables:")
            iptabes=input()
            iptab2mikr(iptabes,False)
            print("\n\nготово - файл routos.txt");
            break
        elif ch=='3':
            print("выходим");
            break
        else:
            print("not correct")
            
    input()


    

    
    
    
