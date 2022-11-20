# **************************************************************************** #
#                                                                              #
#                                                         ::::::::             #
#    Makefile                                           :+:    :+:             #
#                                                      +:+                     #
#    By: novan-ve <novan-ve@student.codam.nl>         +#+                      #
#                                                    +#+                       #
#    Created: 2019/12/20 14:11:17 by novan-ve      #+#    #+#                  #
#    Updated: 2022/09/28 13:43:36 by novan-ve      ########   odam.nl          #
#                                                                              #
# **************************************************************************** #

NAME = libft.a

SRC_DIR = src
OBJ_DIR = obj
INC_DIR = include

SRC = ft_isalnum.c \
		ft_isalpha.c \
		ft_isascii.c \
		ft_isdigit.c \
		ft_isprint.c \
		ft_isspace.c \
		ft_memccpy.c \
		ft_memchr.c \
		ft_memcmp.c \
		ft_memcpy.c \
		ft_memmove.c \
		ft_memset.c \
		ft_putchar_fd.c \
		ft_putendl_fd.c \
		ft_putnbr_fd.c \
		ft_putulong_fd.c \
		ft_putstr_fd.c \
		ft_strlcat.c \
		ft_strlcpy.c \
		ft_strlen.c \
		ft_strcmp.c \
		ft_strncmp.c \
		ft_strnstr.c \
		ft_strchr.c \
		ft_strdup.c \
		ft_strjoin.c \
		ft_strrchr.c \
		ft_substr.c \
		ft_tolower.c \
		ft_toupper.c \
		ft_substr.c \
		ft_strjoin.c \
		ft_strtrim.c \
		ft_itoa.c \
		ft_strmapi.c \
		ft_split.c \
		ft_printf.c \
		ft_printi.c \
		ft_printx.c \
		ft_printp.c \
		ft_prints.c \
		ft_printu.c \
		ft_calc.c \
		ft_atoi.c \
		ft_bzero.c \
		ft_calloc.c \

HEADER = libft.h

OBJ := $(SRC:%.c=./$(OBJ_DIR)/%.o)
SRC := $(SRC:%=./$(SRC_DIR)/%)

HEADER := $(HEADER:%=./$(INC_DIR)/%)

FLAGS = -Wall -Werror -Wextra

all: $(NAME)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(HEADER) | $(OBJ_DIR)
	$(CC) $(FLAGS) -I$(INC_DIR) -c $< -o $@

$(NAME): $(OBJ)
	ar rc $(NAME) $(OBJ)
	ranlib $(NAME)

$(OBJ_DIR):
	mkdir -p $@

clean:
	$(RM) $(OBJ)

fclean: clean
	$(RM) $(NAME)

re: fclean
	$(MAKE)
