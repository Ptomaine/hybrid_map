#pragma once

/***************************************************************************
 *   Copyright (C) 1995, 2013 by Arlen Albert Keshabyan                    *
 *   <arlen.albert@gmail.com>                                              *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#include <vector>
#include <cstring>
#include <string>
#include <iostream>
#include <utility>

namespace hmap
{
    typedef unsigned char uchar_t;

    template <class string_type = std::string>
    class string_adapter
    {
    private:
        const string_type &_data;

    public:

        string_adapter(const string_type &input = string_type()) : _data(input) {}
        const void *data() const { return _data.c_str(); }
        size_t size() const { return _data.size(); }
    };

    class char_adapter
    {
    private:
        const char *_data;

    public:

        char_adapter(const char *input = "\0") : _data(input) {}
        const void *data() const { return _data; }
        size_t size() const { return std::strlen(_data); }
    };

    template<typename simple_type>
    class simple_type_adapter
    {
    private:
        const simple_type &_data;

    public:

        simple_type_adapter(const simple_type &data) : _data(data) {}
        const void *data() const { return &_data; }
        size_t size() const { return sizeof(_data); }
    };

    template<class key_type = char>
    class keys_keeper
    {
    private:
        void **&_keys;
        size_t _keys_size;
        size_t *_key_lengths;
        bool _released;

    public:
        keys_keeper(void **&keys, size_t keys_size, size_t *key_lengths = 0) :
        _keys(keys),
            _keys_size(keys_size),
            _key_lengths(key_lengths),
            _released(false) {}

        ~keys_keeper()
        {
            if (!_released)
            {
                for(size_t index(0); index < _keys_size; delete[] (reinterpret_cast<key_type**>(_keys))[index], ++index) ;

                delete[] _keys;
                delete[] _key_lengths;
            }
        }

        void release() { _released = true; }
        size_t count() const { return _keys_size; }
        size_t size() const { return _keys_size; }

        const key_type* operator [] (size_t index) const { return (reinterpret_cast<key_type**>(_keys))[index]; }
        size_t operator () (size_t index) const { return _key_lengths[index]; }
    };

    template<typename data_type>
    class fast_list
    {
    public:
        class fast_list_node
        {
        private:
            typedef fast_list_node self_type;
            typedef self_type* self_type_ptr;
            typedef self_type& self_type_ref;
            typedef const self_type* self_type_const_ptr;

            self_type_ptr _prev;
            self_type_ptr _next;
            data_type _data;

            friend class fast_list<data_type>;

            self_type_ptr insert_next(const data_type &data)
            {
                return new(std::nothrow) self_type(data, this, _next);
            }

            self_type_ptr insert_prev(const data_type &data)
            {
                return new(std::nothrow) self_type(data, _prev, this);
            }

            self_type_ptr remove(bool destroy = true)
            {
                self_type_ptr ret((_next) ? _next : _prev);

                if (_prev)
                    _prev->_next = _next;

                if (_next)
                    _next->_prev = _prev;

                _prev = _next = 0;

                if (destroy)
                    delete this;

                return ret;
            }

        public:
            fast_list_node(const data_type &data, self_type_ptr const prev = 0, self_type_ptr const next = 0) :
                _prev(prev),
                _next(next),
                _data(data)
              {
                  if (_next)
                      _next->_prev = this;

                  if (_prev)
                      _prev->_next = this;
              }

              ~fast_list_node()
              {
                  if (_next)
                      delete _next;
              }

              data_type &data()
              {
                  return _data;
              }

              self_type_ptr next() const
              {
                  return _next;
              }

              self_type_ptr prev() const
              {
                  return _prev;
              }

              unsigned count() const
              {
                  unsigned count(1);
                  self_type_const_ptr curr(this);

                  while (curr->_next)
                      curr = curr->_next, ++count;

                  curr = this;

                  while (curr->_prev)
                      curr = curr->_prev, ++count;

                  return count;
              }
        };

    public:
        typedef fast_list_node node_type;
        typedef fast_list_node* node_type_ptr;

    private:
        typedef fast_list<data_type> self_type;

        node_type_ptr _head, _tail;

        bool init_if_needed(const data_type &data)
        {
            if (_head)
                return false;

            _head = _tail = new(std::nothrow) node_type(data);

            return true;
        }

    public:
          constexpr fast_list() :
            _head(0),
            _tail(0)
          {
          }

          ~fast_list()
          {
              clear();
          }

          bool empty() const
          {
              return (!_head);
          }

          bool single_node() const
          {
              return (_head && !_head->_prev && !_head->_next);
          }

          node_type_ptr push_back(const data_type &data)
          {
              if (!init_if_needed(data))
                  _tail = _tail->insert_next(data);

              return _tail;
          }

          node_type_ptr push_front(const data_type &data)
          {
              if (!init_if_needed(data))
                  _head = _head->insert_prev(data);

              return _head;
          }

          data_type &front()
          {
              return _head->data();
          }

          data_type &back()
          {
              return _tail->data();
          }

          unsigned size() const
          {
              return (_head) ? _head->count() : 0;
          }

          node_type_ptr head() const
          {
              return _head;
          }

          node_type_ptr tail() const
          {
              return _tail;
          }

          node_type_ptr erase(node_type_ptr node_ptr)
          {
              node_type_ptr node(node_ptr->remove(true));

              if (node_ptr == _head)
                  _head = node;

              if (node_ptr == _tail)
                  _tail = node;

              return node;
          }

          node_type_ptr insert(node_type_ptr node_ptr, const data_type &data)
          {
              if (init_if_needed(data))
                  return _head;

              if (node_ptr == _tail)
                  return push_back(data);

              return node_ptr->insert_next(data);
          }

          void clear()
          {
              node_type_ptr current_node(_tail), prev_node(0);

              while (current_node)
              {
                  prev_node = current_node->_prev;

                  current_node->_next = 0;

                  delete current_node;

                  current_node = prev_node;
              }

              _head = _tail = 0;
          }
    };

	template <class data_type, template<class> class container_policy> class hybrid_map_node;

    template<class data_type>
    class hybrid_map_node_container_policy_ARRAY
    {
    private:
        typedef hybrid_map_node<data_type, hybrid_map_node_container_policy_ARRAY> node_type;
        typedef node_type* node_type_ptr;

        uchar_t _key;
        uchar_t _size;
        node_type_ptr _children[256];

    public:
        hybrid_map_node_container_policy_ARRAY(uchar_t key) :
            _key(key),
            _size(0)
        {
            std::memset(_children, 0, 256 * sizeof(node_type_ptr));
        }

        ~hybrid_map_node_container_policy_ARRAY()
        {
            size_t index(0);

            while (index < 256)
            {
                if (_children[index])
                    delete _children[index];

                index++;
            }
        }

        size_t size() const
        {
            return _size;
        }

        uchar_t key() const
        {
            return _key;
        }

        node_type_ptr get_key(uchar_t key) const
        {
            return _children[key];
        }

        node_type_ptr add(uchar_t key, node_type_ptr parent_node)
        {
            if(_children[key])
                return _children[key];

            _children[key] = new(std::nothrow) node_type(key, parent_node);

            if (_children[key])
                ++_size;

            return _children[key];
        }

        void remove(uchar_t key)
        {
            if (_children[key])
                delete _children[key], _children[key] = 0, --_size;
        }

        node_type_ptr next(uchar_t key) const
        {
            size_t index(key);

            for (; index < 256 && !_children[index]; ++index) ;

            if (index > 255)
                return 0;

            return _children[index];
        }
    };

    template<class data_type>
    class hybrid_map_node_container_policy_FAST_LIST
    {
    private:
        typedef hybrid_map_node<data_type, hybrid_map_node_container_policy_FAST_LIST> node_type;
        typedef node_type* node_type_ptr;
		typedef fast_list<node_type_ptr> children_list_type;
		typedef typename children_list_type::node_type_ptr child_node_type_ptr;

        uchar_t _key;
        uchar_t _size;
		children_list_type _children;

        child_node_type_ptr get_node_ptr(uchar_t key) const
        {
            if (key < 128)
            {
                for (child_node_type_ptr current = _children.head(); current; current = current->next())
                    if (current->data()->_key == key)
                        return current;
            }
            else
            {
                for (child_node_type_ptr current = _children.tail(); current; current = current->prev())
                    if (current->data()->_key == key)
                        return current;
            }

            return 0;
        }

    public:
        hybrid_map_node_container_policy_FAST_LIST(uchar_t key) :
            _key(key),
            _size(0),
            _children()
        {
        }

        ~hybrid_map_node_container_policy_FAST_LIST()
        {
            typename children_list_type::node_type_ptr current = _children.head(), next(0);

            while (current)
            {
                next = current->next();

                delete current->data();

                current = next;
            }
        }

        size_t size() const
        {
            return _size;
        }

        uchar_t key() const
        {
            return _key;
        }

        node_type_ptr get_key(uchar_t key) const
        {
            child_node_type_ptr node(get_node_ptr(key));

            return node ? node->data() : 0;
        }

        node_type_ptr add(uchar_t key, node_type_ptr parent_node)
        {
           node_type_ptr node(get_key(key));

            if(node)
                return node;

            node = new(std::nothrow) node_type(key, parent_node);

            if (node)
            {
                ++_size;

                if (key < 128)
                    return _children.push_front(node)->data();

                return _children.push_back(node)->data();
            }

            return 0;
        }

        void remove(uchar_t key)
        {
            child_node_type_ptr node(get_node_ptr(key));

            if (node)
                _children.erase(node), --_size;
        }

        node_type_ptr next(uchar_t key) const
        {
            node_type_ptr node(get_key(key));

            if(!node)
                return 0;

            node = node->next(key);

            if(!node)
                return 0;

            return node;
        }
    };

	template<class data_type, template<class> class container_type> class hybrid_map;

	template <class data_type, template<class> class container_policy>
	class hybrid_map_node : public container_policy<data_type>
	{
	public:
        typedef container_policy<data_type> children_type;
		typedef hybrid_map_node<data_type, container_policy> self_type;
		typedef self_type* self_type_ptr;

        hybrid_map_node(uchar_t key, self_type_ptr parent) :
            children_type(key),
            _depth(0),
            _parent(parent),
            _data()
        {
        }

        ~hybrid_map_node()
        {
        }

        data_type &data() { return _data; }
        data_type data() const { return _data; }

        size_t size() const
        {
            return children_type::size();
        }

        self_type_ptr get_key(uchar_t key) const
        {
            return children_type::get_key(key);
        }

        self_type_ptr add(uchar_t key)
        {
            return children_type::add(key, this);
        }

        void remove(uchar_t key)
        {
            children_type::remove(key);
        }

        size_t depth() const
        {
            size_t depth(_depth);

            if(!depth)
            {
                self_type_ptr node(const_cast<self_type_ptr>(this));

                while((node = node->_parent))
                    ++depth;
            }

            return depth;
        }

        void path(void *user_buffer, size_t &length, const void *tail = "\0", size_t tail_length = 1)
        {
            uchar_t *chain(static_cast<uchar_t*>(user_buffer));
            length = _depth;

            if(tail && tail_length)
                std::memcpy(chain + length, tail, tail_length);

            self_type_ptr node(this);

            for(int index(length - 1); index >= 0; chain[index] = node->_key, node = node->_parent, --index) ;
        }

        void path(std::vector<uchar_t> &vector)
        {
            size_t length(depth());

            vector.resize(length);

            self_type_ptr node(this);

            for(int index(length - 1); index >= 0; vector[index] = node->_key, node = node->_parent, --index) ;
        }

        self_type_ptr next(uchar_t key) const
        {
            return children_type::next(key);
        }

	private:

		friend class hybrid_map<data_type, container_policy>;

		size_t _depth;
		self_type_ptr _parent;
		data_type _data;
	};

	template <class data_type, template<class> class container_policy = hybrid_map_node_container_policy_FAST_LIST>
	class hybrid_map
	{
	public:
        typedef hybrid_map<data_type, container_policy> self_type;
        typedef self_type* self_type_ptr;
		typedef hybrid_map_node<data_type, container_policy> node_type;
		typedef node_type* node_type_ptr;

        hybrid_map() :
            _root(new node_type(0, 0)),
            _current(_root),
            _size(0)
        {
        }

        ~hybrid_map()
        {
            delete _root;
        }

        size_t size() const
        {
            return _size;
        }

        data_type &insert(const void *path, size_t path_length)
        {
            const uchar_t *byte_path(static_cast<const uchar_t*>(path));

            _current = _root;

            for(size_t index(0); index < path_length && _current; ++index)
                _current = _current->add(byte_path[index]);

            if(_current && !_current->_depth)
            {
                ++_size;

                _current->_depth = path_length;
            }
            else
                _current = _root;

            return _current->_data;
        }

        template<class adapter> data_type &insert(const adapter& proxy)
        {
            return insert(proxy.data(), proxy.size());
        }

        data_type &insert(const void *path, size_t path_length, node_type_ptr &result_node)
        {
            data_type &result_data(insert(path, path_length));

            result_node = _current;

            return result_data;
        }

        template<class adapter> data_type &insert(const adapter& proxy, node_type_ptr &result_node)
        {
            return insert(proxy.data(), proxy.size(), result_node);
        }

        void remove(node_type_ptr node)
        {
            _current = node;

            if(!_current->_depth)
                return;

            --_size;

            _current->_depth = 0;

            if (_current->size() > 0)
            {
                _current = _root;

                return;
            }

            while (_current->_parent != _root && !_current->_parent->_depth && _current->_parent->size() == 1)
                _current = _current->_parent;

            _current->_parent->remove(_current->key());

            _current = _root;
        }

        void remove(const void *path, size_t path_length)
        {
            if (!move_to(path, path_length))
                return;

            remove(_current);
        }

        template<class adapter> void remove(const adapter& proxy)
        {
            return remove(proxy.data(), proxy.size());
        }

        void clear()
        {
            if (_size)
            {
                delete _root;

                _root = new node_type(0, 0);
                _current = _root;
                _size = 0;
            }
        }

        void remove_branch(const void *path, size_t path_length, bool children_only = false)
        {
            if (!move_to(path, path_length))
                return;

            size_t depth = _current->depth(), current_depth(depth);
            node_type_ptr cut_node(_current);

            while (next(_current) && (current_depth = _current->_depth) > depth)
            {
                uchar_t current_path[current_depth];

                _current->path(current_path, current_depth, 0, 0);

                node_type_ptr prepared_node(_current);

                if (move_to(current_path, path_length) && _current == cut_node)
                    remove(prepared_node);
                else
                    break;

                _current = cut_node;
            }

            if (!children_only && move_to(path, path_length) && _current->_depth)
                remove(_current);

            _current = _root;
        }

        template<class adapter> void remove_branch(const adapter& proxy, bool children_only = false)
        {
            return remove_branch(proxy.data(), proxy.size(), children_only);
        }

        data_type &data(const void *path, size_t path_length)
        {
            if (!move_to(path, path_length) || !_current->_depth)
                return _root->_data;

            return _current->_data;
        }

        template<class adapter> data_type &data(const adapter& proxy)
        {
            return data(proxy.data(), proxy.size());
        }

        data_type data(const void *path, size_t path_length) const
        {
            if (!move_to(path, path_length) || !_current->_depth)
                return _root->_data;

            return _current->_data;
        }

        template<class adapter> data_type data(const adapter& proxy) const
        {
            return data(proxy.data(), proxy.size());
        }

        bool find(const void *path, size_t path_length)
        {
            if (!move_to(path, path_length))
                return false;

            return _current->_depth > 0;
        }

        template<class adapter> bool find(const adapter& proxy)
        {
            return find(proxy.data(), proxy.size());
        }

        bool find(const void *path, size_t path_length, data_type &stored_data)
        {
            if (!move_to(path, path_length))
                return false;

            if (_current->_depth)
                stored_data = _current->_data;

            return _current->_depth > 0;
        }

        template<class adapter> bool find(const adapter& proxy, data_type &stored_data)
        {
            return find(proxy.data(), proxy.size(), stored_data);
        }

        bool find(const void *path, size_t path_length, node_type_ptr &node)
        {
            if (!move_to(path, path_length))
                return false;

            if (_current->_depth)
                node = _current;

            return _current->_depth > 0;
        }

        template<class adapter> bool find(const adapter& proxy, node_type_ptr &node)
        {
            return find(proxy.data(), proxy.size(), node);
        }

        node_type_ptr node(const void *path, size_t path_length)
        {
            if (!move_to(path, path_length))
                return 0;

            return _current;
        }

        template<class adapter> node_type_ptr node(const adapter& proxy)
        {
            return node(proxy.data(), proxy.size());
        }

        node_type_ptr root() const
        {
            return _root;
        }

        node_type_ptr current() const
        {
            return _current;
        }

        bool next(node_type_ptr &from_node) const
        {
            if (!from_node)
                return false;

            if (!from_node->_size)
            {
                while (from_node)
                {
                    node_type_ptr previous_node(from_node), backup_node(0);

                    from_node = from_node->_parent;

                    while (from_node && from_node->_size == 1)
                    {
                        previous_node = from_node;
                        from_node = from_node->_parent;
                    }

                    if (!from_node)
                        return false;

                    backup_node = from_node;

                    from_node = from_node->next(previous_node->_key + 1);

                    if (!from_node)
                        from_node = backup_node;
                    else
                        break;
                }

                if (from_node->_depth)
                    return from_node;
            }

            node_type_ptr next_node(from_node->next(0));

            if (!__next(next_node, next_node))
                return (from_node = 0), false;

            return (from_node = next_node), true;
        }

        size_t keys(void **&keys, size_t **key_lengths = 0, const void *tail = "\0", size_t tail_length = 1)
        {
            size_t result(0);

            keys = new void*[_size];

            if (key_lengths)
                (*key_lengths) = new size_t[_size];

            __keys(_current, keys, result, key_lengths, tail, tail_length);

            return result;
        }

        void keys(std::vector<std::vector<uchar_t> > &keys)
        {
            keys.resize(_size);

            size_t indexer(0);

            __keys(_current, keys, indexer);
        }

        bool move_to(const void *path = 0, size_t path_length = 0, node_type_ptr from_node = 0) const
        {
            _current = (from_node) ? from_node : _root;

            if (!path || !path_length)
                return true;

            const uchar_t *byte_path(static_cast<const uchar_t*>(path));
            node_type_ptr node(_root);

            for (size_t index(0); index < path_length; ++index)
                if (!(node = node->get_key(byte_path[index])))
                    return false;

            _current = node;

            return true;
        }

        template<class adapter> bool move_to(const adapter& proxy, node_type_ptr from_node = 0) const
        {
            return move_to(proxy.data(), proxy.size(), from_node);
        }

        bool shift_fwd(const void *path = 0, size_t path_length = 0)
        {
            return move_to(path, path_length, _current);
        }

        template<class adapter> bool shift_fwd(const adapter& proxy)
        {
            return move_to(proxy.data(), proxy.size(), _current);
        }

        bool shift_bwd(size_t steps = 1)
        {
            if (!_current->_parent || !steps)
                return false;

            while (_current->_parent && steps--) _current = _current->_parent;

            return true;
        }

        template<class hybrid_map_callback> int scan(hybrid_map_callback callback, void *user_data = 0, node_type_ptr node = 0)
        {
            node_type_ptr from_node(((node) ? node : _root));
            int result(__scan(from_node, callback, user_data));

            _current = from_node;

            return result;
        }

        hybrid_map(const self_type &copy) :
            _root(new node_type(0, 0)),
            _current(_root),
            _size(0)
        {
            __copy(copy);
        }

        self_type &operator = (const self_type &copy)
        {
            __copy(copy);

            return *this;
        }

        bool at_root() const
        {
            return (_current == _root);
        }

        template<class adapter> data_type &operator [] (const adapter &proxy)
        {
            return insert(proxy);
        }

        template<class adapter> data_type operator [] (const adapter &proxy) const
        {
            return data(proxy);
        }

	private:

		node_type_ptr _root;
		mutable node_type_ptr _current;
		size_t _size;

        void __copy(const self_type &copy)
        {
            clear();

            node_type_ptr next(copy._root);

            std::vector<uchar_t> path;

            while (copy.next(next))
            {
                next->path(path);

#ifndef _MSC_VER
                insert(path) = next->data();
#else
                // MS STL does not support data() member function of vector
                insert(&path[0], path.size()) = next->data();
#endif
            }
        }

        template<class hybrid_map_callback> int __scan(node_type_ptr node, hybrid_map_callback callback, void *user_data)
        {
            int result(0);

            if (node->_depth && (result = callback(node, user_data)))
                return result;

            for (size_t index(0); index < 256; ++index)
                if (node->_children[index] && (result = __scan(node->_children[index], callback, user_data)))
                    return result;

            return result;
        }

        void __keys(node_type_ptr node, std::vector<std::vector<uchar_t> > &keys, size_t &indexer)
        {
            if(node->_depth)
            {
                keys[indexer].resize(node->_depth);

                node_type_ptr current_node(node);

                for (int index(node->_depth - 1); index >= 0; --index)
                {
                    keys[indexer][index] = current_node->_key;
                    current_node = current_node->_parent;
                }

                ++indexer;
            }

            node_type_ptr next_node(node->next(0));

            while (next_node)
            {
                __keys(next_node, keys, indexer);

                next_node = node->next(next_node->_key + 1);
            }
        }

        void __keys(node_type_ptr node, void **&keys, size_t &indexer, size_t **key_lengths, const void *tail, size_t tail_length)
        {
            if (node->_depth)
            {
                uchar_t **paths(reinterpret_cast<uchar_t**>(keys));

                keys[indexer] = new uchar_t[node->_depth + ((tail && tail_length) ? tail_length : 0)];

                node_type_ptr current_node(node);

                for(int index(node->_depth - 1); index >= 0; --index)
                {
                    paths[indexer][index] = current_node->_key;
                    current_node = current_node->_parent;
                }

                if (tail && tail_length)
                    std::memcpy(paths[indexer] + node->_depth, tail, tail_length);

                if (key_lengths)
                    (*key_lengths)[indexer] = node->_depth;

                ++indexer;
            }

            node_type_ptr next_node(node->next(0));

            while (next_node)
            {
                __keys(next_node, keys, indexer, key_lengths, tail, tail_length);

                next_node = node->next(next_node->_key + 1);
            }
        }

        bool __next(node_type_ptr node, node_type_ptr &result_node) const
        {
            if (node->_depth)
            {
                result_node = node;

                return true;
            }

/*#ifdef USE_AGGRESSIVE_MEMORY_POLICY
            for (size_t index(0); index < 256; ++index)
                if(node->_children->get_key(index) && __next(node->_children->get_key(index), result_node))
                    return true;
#else*/
            node_type_ptr node_ = node->_children.head();

            while(node_)
            {
                if(__next(node_->data(), result_node))
                        return true;

                node_ = node_->next();
            }

            return false;
        }
	};


template<class data_type, template<class> class container_policy>
struct ptr_deleter
{
	int operator () (hmap::hybrid_map_node<data_type, container_policy> *item, void *) { delete item->data(); return 0; }
};

template<class data_type, template<class> class container_policy>
struct array_ptr_deleter
{
	int operator () (hmap::hybrid_map_node<data_type, container_policy> *item, void *) { delete[] item->data(); return 0; }
};

}

