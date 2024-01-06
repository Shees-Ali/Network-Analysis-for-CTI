#pragma once
#include <iostream>
#include <vector>

using namespace std;

struct HeapObject{
	string data;
	int frequence;
    HeapObject(string data) {
        this->data = data;
        this->frequence = 0;
    }
};

class Heap {
    vector<HeapObject> HeapTree;
public:
    void swap(HeapObject* a, HeapObject* b)
    {
        HeapObject temp = *b;
        *b = *a;
        *a = temp;
    }
    void heapify(int i)
    {
        int size = HeapTree.size();
        int largest = i;
        int l = 2 * i + 1;
        int r = 2 * i + 2;

        if (l < size && HeapTree[l].frequence > HeapTree[largest].frequence)
            largest = l;
        if (r < size && HeapTree[r].frequence > HeapTree[largest].frequence)
            largest = r;
        if (largest != i)
        {
            swap(&HeapTree[i], &HeapTree[largest]);
        }
    }
    void insert(string data)
    {
        int size = HeapTree.size();
        if (Search(data) > -1) {
            
            for (int i = size / 2 - 1; i >= 0; i--)
                heapify(i);
        }
        else {
            // if the heap is empty, insert the new element
            if (size == 0)
                HeapTree.push_back(HeapObject(data));
            else
            {
                // insert at the end of the vector
                HeapTree.push_back(HeapObject(data));
                for (int i = size / 2 - 1; i >= 0; i--)
                    heapify(i);
            }
        }
    }

    int Search(string data) {
        int size = HeapTree.size();
        if (size == 0)
        {
            return -1;
        }
        int i;
        for (i = 0; i < size; i++)
        {
            if (data == HeapTree[i].data)
            {
                HeapTree[i].frequence++;
                return i;
                break;
            }
        }
        if (i == size)
        {
            return -1;
        }

        return -1;
    }

    string GetLargest() {
        int size = HeapTree.size();
        for (int i = size / 2 - 1; i >= 0; i--)
            heapify(i);

        return HeapTree[0].data;
    }
};