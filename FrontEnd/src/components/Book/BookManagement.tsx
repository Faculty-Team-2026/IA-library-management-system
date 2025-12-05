import React, { useState, useEffect } from "react";
import axios from "axios";
import BookAddDialog from "./BookAddDialog";
import BookTable from "./BookTable";
import BookSearchBar from "./BookSearchBar.tsx";
import BookEditDialog from "./BookEditDialog";
import { Book } from "../../types/book";

interface BookManagementProps {
  containerClassName?: string;
  searchBarClassName?: string;
  tableClassName?: string;
  onAddClick?: () => void;
  onEditClick?: (book: Book) => void;
  onDeleteClick?: (id: number) => void;
  customActions?: React.ReactNode;
}

const BookManagement: React.FC<BookManagementProps> = ({
  containerClassName = "",
  searchBarClassName = "",
  tableClassName = "",
  onAddClick,
  onEditClick,
  onDeleteClick,
  customActions,
}) => {
  const [books, setBooks] = useState<Book[]>([]);
  const [newBook, setNewBook] = useState({
    title: "",
    author: "",
    isbn: "",
    quantity: 0,
    description: "",
  });
  const [newBookImage, setNewBookImage] = useState<File | null>(null);
  const [editingBook, setEditingBook] = useState<Book | null>(null);
  const [editBookImage, setEditBookImage] = useState<File | null>(null);
  const [search, setSearch] = useState("");
  const [isAddDialogOpen, setIsAddDialogOpen] = useState(false);
  const [addError, setAddError] = useState<string | null>(null);
  const [editError, setEditError] = useState<string | null>(null);

  useEffect(() => {
    axios
      .get("/Books")
      .then((response) => {
        const data = Array.isArray(response.data)
          ? response.data.map((b: Book) => ({
              id: b.id,
              title: b.title,
              author: b.author,
              isbn: b.isbn,
              coverImage: b.coverImage,
              coverImageContentType: b.coverImageContentType,
              available: b.available,
              quantity: b.quantity,
              description: b.description,
            }))
          : [];
        setBooks(data);
      })
      .catch((error) => console.error("Error fetching books:", error));
  }, []);

  const handleAddBook = (event?: React.FormEvent) => {
    if (event) event.preventDefault();
    setAddError(null);
    if (newBook.title && newBook.author && newBook.isbn) {
      const formData = new FormData();
      formData.append("Title", newBook.title);
      formData.append("Author", newBook.author);
      formData.append("ISBN", newBook.isbn);
      formData.append("Quantity", String(newBook.quantity));
      formData.append("Description", newBook.description || "");
      if (newBookImage) {
        formData.append("CoverImageFile", newBookImage);
      }
      axios
        .post("/Books", formData, {
          headers: { "Content-Type": "multipart/form-data" },
        })
        .then((response) => {
          const b = response.data;
          setBooks([
            ...books,
            {
              id: b.id,
              title: b.title,
              author: b.author,
              isbn: b.isbn,
              coverImage: b.coverImage,
              coverImageContentType: b.coverImageContentType,
              available: b.available,
              quantity: b.quantity,
              description: b.description,
            },
          ]);
          setNewBook({
            title: "",
            author: "",
            isbn: "",
            quantity: 0,
            description: "",
          });
          setNewBookImage(null);
          setIsAddDialogOpen(false);
        })
        .catch((error) => {
          console.error("Error adding book:", error);
          setAddError(error.response?.data?.message || "Failed to add book");
        });
    } else {
      setAddError("Title, Author, and ISBN are required");
    }
  };

  const handleEditBook = (book: Book) => {
    setEditingBook({ ...book });
    if (onEditClick) {
      onEditClick(book);
    }
  };

  const handleSaveBook = (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingBook) return;

    const formData = new FormData();
    formData.append("Title", editingBook.title);
    formData.append("Author", editingBook.author);
    formData.append("ISBN", editingBook.isbn || "");
    formData.append("Quantity", String(editingBook.quantity));
    formData.append("Description", editingBook.description || "");
    if (editBookImage) {
      formData.append("CoverImageFile", editBookImage);
    }

    axios
      .put(`/Books/${editingBook.id}`, formData, {
        headers: { "Content-Type": "multipart/form-data" },
      })
      .then((response) => {
        const b = response.data;
        setBooks(
          books.map((book) =>
            book.id === editingBook.id
              ? {
                  id: b.id,
                  title: b.title,
                  author: b.author,
                  isbn: b.isbn,
                  coverImage: b.coverImage,
                  coverImageContentType: b.coverImageContentType,
                  available: b.available,
                  quantity: b.quantity,
                  description: b.description,
                }
              : book
          )
        );
        setEditingBook(null);
        setEditBookImage(null);
        setEditError(null);
      })
      .catch((error) => {
        console.error("Error updating book:", error);
        setEditError(error.response?.data?.message || "Failed to update book");
      });
  };

  const handleDeleteBook = (id: number) => {
    axios
      .delete(`/Books/${id}`)
      .then(() => {
        setBooks(books.filter((book) => book.id !== id));
        if (onDeleteClick) {
          onDeleteClick(id);
        }
      })
      .catch((error) => console.error("Error deleting book:", error));
  };

  const filteredBooks = books.filter(
    (book) =>
      book.title.toLowerCase().includes(search.toLowerCase()) ||
      book.author.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className={`px-2 sm:px-4 py-4 ${containerClassName}`}>
      <BookAddDialog
        open={isAddDialogOpen}
        onClose={() => {
          setIsAddDialogOpen(false);
          setNewBook({
            title: "",
            author: "",
            isbn: "",
            quantity: 0,
            description: "",
          });
          setNewBookImage(null);
          setAddError(null);
        }}
        onSubmit={handleAddBook}
        newBook={newBook}
        setNewBook={setNewBook}
        newBookImage={newBookImage}
        setNewBookImage={setNewBookImage}
        addError={addError}
      />
      <BookEditDialog
        open={!!editingBook}
        onClose={() => {
          setEditingBook(null);
          setEditBookImage(null);
          setEditError(null);
        }}
        onSubmit={handleSaveBook}
        editingBook={editingBook}
        setEditingBook={setEditingBook}
        editError={editError}
        setEditBookImage={setEditBookImage}
      />
      <div className="max-w-7xl mx-auto">
        <BookSearchBar
          search={search}
          setSearch={setSearch}
          onAdd={() => {
            setIsAddDialogOpen(true);
            if (onAddClick) {
              onAddClick();
            }
          }}
          className={`mb-4 ${searchBarClassName}`}
        />
        <BookTable
          books={filteredBooks}
          handleEditBook={handleEditBook}
          handleDeleteBook={handleDeleteBook}
          className={tableClassName}
          customActions={customActions}
        />
      </div>
    </div>
  );
};

export default BookManagement;
