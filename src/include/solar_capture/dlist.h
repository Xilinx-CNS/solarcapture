/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \file
 * \brief sc_dlist: A doubly-linked list.
 *
 * A doubly-linked list always has one item with no data at the head. This can
 * be used by embedding dlist in a parent struct.
 *
 * For example:
 *
 *     #include <stdio.h>
 *     #include <stdlib.h>
 *     #include <solar_capture.h>
 *
 *     int main()
 *     {
 *         struct my_struct {
 *           int my_int;
 *           double my_double;
 *           struct sc_dlist list_ptr;
 *         };
 *
 *         struct sc_dlist my_list;
 *         sc_dlist_init(&my_list);
 *         int i;
 *         struct my_struct* element;
 *         // Add some elements to the list
 *         for( i=0; i < 10; ++i )
 *         {
 *           element = malloc(sizeof(struct my_struct));
 *           element->my_int = i;
 *           element->my_double = i;
 *           sc_dlist_push_tail(&my_list, &element->list_ptr);
 *         }
 *         // cycle over the list
 *         SC_DLIST_FOR_EACH_OBJ(&my_list, element, list_ptr)
 *           printf("element->my_int=%d, element->my_double=%f\n", element->my_int, element->my_double);
 *
 *         // remove each item from the list
 *         struct sc_dlist* list_ptr;
 *         while( !sc_dlist_is_empty(&my_list) ) {
 *           list_ptr = sc_dlist_pop_tail(&my_list);
 *           element = SC_CONTAINER(struct my_struct, list_ptr, list_ptr);
 *           printf("Just popped element with element->my_int=%d", element->my_int);
 *           free(element);
 *         }
 *     }
 *
 *
 *
 */

#ifndef __SOLAR_CAPTURE_DLIST_H__
#define __SOLAR_CAPTURE_DLIST_H__

/**
 * \brief Doubly linked list pointers.
 */
struct sc_dlist {
  struct sc_dlist* prev; /**< A pointer to previous item in list (set to itself if it is at the start of the list).*/
  struct sc_dlist* next; /**< A pointer to next item in list (set to itself if it is at the end of the list).*/
};

/**
 * \brief Get pointer to container from pointer to member.
 * \param c_type     The container type.
 * \param mbr_name   The name of the member in c_type.
 * \param p_mbr      Pointer to the member.
 */
#define SC_CONTAINER(c_type, mbr_name, p_mbr)                           \
  ( (c_type*) ((char*)(p_mbr) - SC_MEMBER_OFFSET(c_type, mbr_name)) )

/**
 * \brief Create a for statement that loops over each container item in the list.
 * It is not safe to modify the list using this macro, if list modifications
 * are required see ::SC_DLIST_FOR_EACH_OBJ_SAFE.
 * \param list       A pointer to the head of the ::sc_dlist.
 * \param iter       A pointer of the same type as the container.
 * \param mbr        The name of the field in the container containing the
 *                   ::sc_dlist struct.
 */
#define SC_DLIST_FOR_EACH_OBJ(list, iter, mbr)                          \
  for( (iter) = SC_CONTAINER(typeof(*(iter)), mbr, (list)->next);       \
       &(iter)->mbr != (list);                                          \
       (iter) = SC_CONTAINER(typeof(*(iter)), mbr, (iter)->mbr.next) )
/**
 * \brief Create a for statement that loops over each container item in the list
 * which can be safely be modified during traversal.
 * \param list       A pointer to the head of the ::sc_dlist.
 * \param iter       A pointer of the same type as the container.
 * \param next_entry A pointer of the same type as the container.
 * \param mbr        The name of the field in the container containing the
 *                   ::sc_dlist struct.
 */
#define SC_DLIST_FOR_EACH_OBJ_SAFE(list, iter, next_entry, mbr)              \
  for( (iter) = SC_CONTAINER(typeof(*(iter)), mbr, (list)->next),            \
       (next_entry) = SC_CONTAINER(typeof(*(iter)), mbr, (iter)->mbr.next);  \
       &(iter)->mbr != (list);                                               \
       (iter) = (next_entry),                                                \
       (next_entry) = SC_CONTAINER(typeof(*(iter)), mbr, (iter)->mbr.next) )

/** \brief Initialise a pre-allocated ::sc_dlist to be an empty doubly linked
 * list
 * \param list       A pointer to the pre-allocated ::sc_dlist to be initialised.
 */
static inline void sc_dlist_init(struct sc_dlist* list)
{
  list->next = list->prev = list;
}

/** \brief Check if a doubly linked list is empty, returns 1 if true
 * 0 otherwise
 */
static inline int sc_dlist_is_empty(const struct sc_dlist* list)
{
  return list->next == list;
}

/** \brief Prepend an item to the head of a doubly-linked list
 * \param list       The list to prepend to.
 * \param l          The item to prepend to @p list.
 */
static inline void sc_dlist_push_head(struct sc_dlist* list, struct sc_dlist* l)
{
  l->next = list->next;
  l->prev = list;
  list->next = l->next->prev = l;
}

/** \brief Append an item to the tail of a doubly-linked list
 * \param list       The list to append to.
 * \param l          The item to append to @p list.
 */
static inline void sc_dlist_push_tail(struct sc_dlist* list, struct sc_dlist* l)
{
  l->next = list;
  l->prev = list->prev;
  list->prev = l->prev->next = l;
}

/** \brief Remove an item from the list
 * \param l          The item to remove.
 */
static inline void sc_dlist_remove(struct sc_dlist* l)
{
  l->prev->next = l->next;
  l->next->prev = l->prev;
}

/** \brief Pop off the head of a list
 * \param list       The point to pop the head from.
 * \return           The item popped from @p list.
 */
static inline struct sc_dlist* sc_dlist_pop_head(struct sc_dlist* list)
{
  struct sc_dlist* l;
  l = list->next;
  sc_dlist_remove(l);
  return l;
}

/** \brief Pop the tail of a list.
 * \param list       The point to pop the tail from.
 * \return           The item popped from @p list.
 */
static inline struct sc_dlist* sc_dlist_pop_tail(struct sc_dlist* list)
{
  struct sc_dlist* l;
  l = list->prev;
  sc_dlist_remove(l);
  return l;
}

/** \brief Replace an item in a list with another item.
 * \param to_list       The item to add to the list, replacing @p from_list.
 * \param from_list     The item to remove from the list.
 */
static inline void sc_dlist_rehome(struct sc_dlist* to_list,
                                   struct sc_dlist* from_list)
{
  if( ! sc_dlist_is_empty(from_list) ) {
    to_list->next = from_list->next;
    to_list->prev = from_list->prev;
    from_list->next->prev = from_list->prev->next = to_list;
    sc_dlist_init(from_list);
  }
  else {
    sc_dlist_init(to_list);
  }
}


#endif  /* __SOLAR_CAPTURE_DLIST_H__ */
/**@}*/
