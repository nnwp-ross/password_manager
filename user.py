import csv
import encryption
import setup
from difflib import SequenceMatcher

directory = setup.directory
hash_file = setup.output_hash

class User:
    def __init__(self, name=None, site=None, user=None, pword=None, note=None):
        if name is not None and site is not None and user is not None and pword is not None:
            self.name = name
            self.site = site
            self.user = user
            self.pword = pword
        else:
            self.name = ""
            self.site = ""
            self.user = ""
            self.pword = ""

        if note is not None:
            self.note = note
        else:
            self.note = ""

    def getName(self):
        return self.name

    def getSite(self):
        return self.site

    def getUser(self):
        return self.user

    def getPword(self):
        return self.pword
    
    def getNote(self):
        return self.note

    def setName(self, name):
        self.name = name

    def setSite(self, site):
        self.site = site
    
    def setUser(self, user):
        self.user = user

    def setPword(self, pword):
        self.pword = pword

    def setNote(self, note):
        self.note = note

    #prints user with or without passwords
    def printUser(self, ask=False):
        print(f"Name:     {self.getName()}")
        print(f"Site:     {self.getSite()}")
        print(f"User:     {self.getUser()}")
        if ask:
            print(f"Password: {self.getPword()}")
            if self.note:
                print(f"Note:     {self.getNote()}")
        print("")

    #returns user in form of list
    def listFormat(self):
        return [self.name, self.site, self.user, self.pword, self.note]

def pass_auth():
    while True:
        ask = input("Print passwords too? 1/0\n")
        if ask in ["0", "1"]:
            ask = bool(int(ask))
            break
        else:
            print("Invalid input.")

    if ask:
        if not encryption.hash_auth(hash_file):
            ask = False

    return ask

def is_similar(str1, str2, threhold):
    ratio = SequenceMatcher(None, str1, str2).ratio()
    return ratio >= threhold

#prints list of names found
def findName(list, name):
    #Ai version (better)
    ask = pass_auth()
    find = set(name.upper().split())
    printed = set()
    for i, item in enumerate(list):
        words = set(item.getName().upper().split())
        if any(is_similar(word, j, 0.7) for word in words for j in find):
            if i not in printed:
                printed.add(i)
                print(f"index: {i}")
                item.printUser(ask)
    #my version (slower)
    '''
    for i in range(len(list)):
        words = set(list[i].getName().upper().split())
        for word in words:
            for j in find:
                if is_similar(word, j, 0.7):
                    if not i in printed:
                        printed.add(i)
                        print(f"index: {i}")
                        list[i].printUser(ask)
    '''
    
#returns list of sites found (Unused)
def findSite(list, site):
    find = []
    for i in range(len(list)):
        if(list[i].getSite().upper() == site.upper()):
            find.append(list[i])
    return find

#prints any list + index
def printList(list):
    ask = pass_auth()

    for i in range(len(list)):
        print(f"index: {i}")
        list[i].printUser(ask)

#prints list of names if found
def findUser(list):    
    name = input("Name of site?: ")
    findName(list, name)

#creates new user to list
def addUser(list):
    vName = input("Input the name: ")
    vSite = input("Input the site: ")
    vUser = input("Input the user: ")
    vPass = encryption.genPass()
            
    vNote = input("Input note (optional): ")

    newUser = User(vName, vSite, vUser, vPass, vNote)
    list.append(newUser)
    print("\nUser added.")
    print(f"index: {list.__len__()-1}")
    newUser.printUser()

#deletes user from list using its index
def delUser(list):
    select = input("which index? ")
    if (str(len(list)) <= select) or (select == "") or (select < "0"):
        print("Index out of boundary.")
    else:
        valid = input("Are you sure? (1/0) ")
        if (valid == "1" and encryption.hash_auth(hash_file)):
            list.remove(list[int(select)])
            print("User removed")

#edits any attribute of a user using its index
def editUser(list):
    select = input("which index? ")
    if not select == "":
        ask = input("name/site/user/pass/note/all (1/2/3/4/5/6): ")
        #edits name
        if ask == "1":
            vName = input("Input the name: ")
            list[int(select)].setName(vName)
            print(f"index: {select}")
            list[int(select)].printUser()
        #edits site
        elif ask == "2":
            vSite = input("Input the site: ")
            list[int(select)].setSite(vSite)
            print(f"index: {select}")
            list[int(select)].printUser() 
        #edits user
        elif ask == "3":
            vUser = input("Input the user: ")
            list[int(select)].setUser(vUser)
            print(f"index: {select}")
            list[int(select)].printUser() 
        #edits password
        elif ask == "4":
            if encryption.hash_auth(hash_file):
                vPass = encryption.genPass()
                list[int(select)].setPword(vPass)
                print(f"index: {select}")
                list[int(select)].printUser(True)
        #edits note
        elif ask == "5":
            vNote = input("Input note (optional): ")
            list[int(select)].setNote(vNote)
            print(f"index: {select}")
            list[int(select)].printUser()
        #edits all attributes
        elif ask == "6":
            vName = input("Input the name: ")
            vSite = input("Input the site: ")
            vUser = input("Input the user: ")
            vPass = encryption.genPass()

            vNote = input("Input note (optional): ")

            list[int(select)].setName(vName)
            list[int(select)].setSite(vSite) 
            list[int(select)].setUser(vUser) 
            list[int(select)].setPword(vPass)
            list[int(select)].setNote(vNote)

            print(f"index: {select}")
            list[int(select)].printUser(True)