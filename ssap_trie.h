

/* simple suffix base and add only patricia trie */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "list.h"

struct ssap_trie {
	struct list_head next;
	struct list_head sibling;

	char ch;
	void * data;
};

struct ssap_trie *
ssap_trie_new (char ch) {

	struct ssap_trie * trie;

	trie = (struct ssap_trie *) malloc (sizeof (struct ssap_trie));
	memset (trie, 0, sizeof (struct ssap_trie));
	INIT_LIST_HEAD (&trie->next);
	INIT_LIST_HEAD (&trie->sibling);
	trie->ch = ch;

	return trie;
}


struct ssap_trie *
ssap_trie_search (struct ssap_trie * root, char * word)
{
	int n;
	struct ssap_trie * trie;
	struct list_head * tmp_head, * cur, * next;

	trie = root;
	tmp_head = &root->next;
	
	for (n = strlen (word); n >= 0; n--) {

		if (tmp_head != &root->next && list_empty (tmp_head)) {
			/* longest matched! */
			return trie;
		}

		list_for_each_safe (cur, next, tmp_head) {
			trie = list_entry (cur, struct ssap_trie, sibling);

			if (trie->ch == word[n]) {
				/* match! next character! */
				tmp_head = &trie->next;
				goto next_depth;
			}

		}

		/* there is no next character leaf. not found!  */
		return NULL;

	next_depth:;
	}

	if (n < 0 && list_empty (tmp_head)) {
		/* perfect match. query = match name !! */
		return trie;
	}

	return NULL;
}

int
ssap_trie_walk (struct ssap_trie * root, void (*func)(void *))
{
	struct ssap_trie * trie;
	struct list_head * tmp_head, * cur, * next;

	tmp_head = &root->next;

	if (root->data) {
		func (root->data);
	}

	list_for_each_safe (cur, next, tmp_head) {
		trie = list_entry (cur, struct ssap_trie, sibling);
		ssap_trie_walk (trie, func);
	}

	return 0;
}

int
ssap_trie_add (struct ssap_trie * root, char * word, void * data)
{
	int n;
	struct ssap_trie * trie, * parent;
	struct list_head * tmp_head, * cur, * next;

	parent = root;
	tmp_head = &root->next;
	
	for (n = strlen (word); n >= 0; n--) {

		list_for_each_safe (cur, next, tmp_head) {
			trie = list_entry (cur, struct ssap_trie, sibling);

			if (trie->ch == word[n]) {
				/* match! next character! */
				goto next_depth;
			}
		}

		/* there is no next character. add new node! */
		trie = ssap_trie_new (word[n]);
		if (n == 0) {
			/* edge leaf. add data. */
			trie->data = data;
		}
		list_add_tail (&trie->sibling, &parent->next);

	next_depth:
		tmp_head = &trie->next;
		parent = trie;
	}

	return 1;
}


