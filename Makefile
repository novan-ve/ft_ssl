NAME = ft_ssl

SRC_DIR = src
OBJ_DIR = obj
INC_DIR = include

SRC = main.c \
		bitwise.c \
		commands.c \
		ftarg.c \
		ftio.c \
		fterror.c \
		ftmath.c \
		handle_base64.c \
		handle_des.c \
		handle_digest.c \
		handle_genrsa.c \
		handle_rsa.c \
		handle_rsautl.c \
		hex_utils.c \
		base64.c \
		des.c \
		hmac.c \
		md5.c \
		pbkdf.c \
		rand.c \
		rsa.c \
		rsa_print.c \
		rsa_read.c \
		rsa_validate.c \
		sha1.c \
		sha256.c

INC = base64.h \
		bitwise.h \
		commands.h \
		des.h \
		digest.h \
		ftarg.h \
		ftio.h \
		fterror.h \
		ftmath.h \
		hex_utils.h \
		hmac.h \
		md5.h \
		pbkdf.h \
		rand.h \
		rsa.h \
		sha1.h \
		sha256.h

LIBFT = libft/libft.a
LIBFT_INC = libft.h
LIBFT_INC_DIR = libft/include

OBJ := $(SRC:%.c=./$(OBJ_DIR)/%.o)
SRC := $(SRC:%=./$(SRC_DIR)/%)

INC := $(INC:%=./$(INC_DIR)/%)
LIBFT_INC := $(LIBFT_INC:%=./$(LIBFT_INC_DIR)/%)

FLAGS = -Wall -Werror -Wextra

all: $(NAME)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(INC) $(LIBFT_INC) | $(OBJ_DIR)
	$(CC) $(FLAGS) $(CFLAGS) -I$(INC_DIR) -I$(LIBFT_INC_DIR) -c $< -o $@

$(NAME): $(OBJ)
	$(MAKE) -s -C libft
	$(CC) $^ -o $@ $(LIBFT)

$(OBJ_DIR):
	mkdir -p $@

clean:
	$(RM) $(OBJ)
	$(MAKE) -C libft clean

fclean:
	$(RM) $(OBJ) $(NAME)
	$(MAKE) -C libft fclean

re: fclean
	$(MAKE)
