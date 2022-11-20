/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_printi.c                                        :+:    :+:            */
/*                                                     +:+                    */
/*   By: novan-ve <novan-ve@student.codam.nl>         +#+                     */
/*                                                   +#+                      */
/*   Created: 2019/12/17 17:16:01 by novan-ve      #+#    #+#                 */
/*   Updated: 2022/05/25 16:03:43 by novan-ve      ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int		ft_nbrleni(long nb, int x)
{
	int				i;

	i = 0;
	if (nb == 0)
		return (1);
	if (nb < 0 && x == 0)
		i = 1;
	while (nb > 0 || nb < 0)
	{
		nb /= 10;
		i++;
	}
	return (i);
}

void	ft_printi3(t_print *p, int j, int k)
{
	int		i;

	i = 0;
	while (i < (p->prec - p->tmplen))
	{
		p->len++;
		ft_putchar_fd('0', p->fd);
		i++;
	}
	if (k != 1)
		ft_putnbr_fd(p->itmp, p->fd);
	i = 0;
	if (p->just == 'r')
		while (i < p->tmpwidth - p->tmplen && i < p->tmpwidth - p->prec)
		{
			p->len++;
			ft_putchar_fd(p->padchar, p->fd);
			i++;
		}
	if (j == 1)
		p->tmpwidth++;
}

int		ft_printi2(t_print *p, int j)
{
	int		i;

	i = 0;
	if (p->prec == -1)
		p->prec = 0;
	if (p->itmp < 0)
	{
		if (p->padchar == '0')
			ft_putchar_fd('-', p->fd);
		p->tmplen--;
		p->itmp = -p->itmp;
		p->len++;
		p->tmpwidth--;
		j = 1;
	}
	if (p->just == 'l')
	{
		while (i < p->tmpwidth - p->tmplen && i < p->tmpwidth - p->prec)
		{
			p->len++;
			ft_putchar_fd(p->padchar, p->fd);
			i++;
		}
	}
	return (j);
}

void	ft_printi(t_print *p)
{
	int		j;
	int		k;

	j = 0;
	k = 0;
	p->itmp = va_arg(p->args, int);
	p->tmplen += ft_nbrleni(p->itmp, 0);
	if (p->tmplen < p->tmpwidth || p->prec != -1)
	{
		if (p->prec == 0 && p->itmp == 0)
		{
			p->tmplen = 0;
			k = 1;
		}
		j = ft_printi2(p, j);
		if (j == 1 && p->padchar != '0')
			ft_putchar_fd('-', p->fd);
		ft_printi3(p, j, k);
	}
	else
		ft_putnbr_fd(p->itmp, p->fd);
}

void	ft_printper(t_print *p)
{
	int		i;

	i = 0;
	p->len++;
	while (i < p->tmpwidth - 1 && p->just == 'l')
	{
		ft_putchar_fd(p->padchar, p->fd);
		i++;
		p->len++;
	}
	ft_putchar_fd('%', p->fd);
	while (i < p->tmpwidth - 1 && p->just == 'r')
	{
		ft_putchar_fd(p->padchar, p->fd);
		i++;
		p->len++;
	}
}
